"""Ключ авторизации, статистика и диагностика WSBridge Relay.

Дизайн-ограничения (сформулированы владельцем):
- стабильность и самоподъём;
- максимальная детальность при ошибках;
- минимум ресурсов: 2-5 активных клиентов, всё остальное — по минимуму.

Память: счётчики — десятки int; кольцо диагностики — ограничено
DIAG_MAX записями x DIAG_LINE_MAX байт; файл статистики — один JSON.
Ничего не может расти неограниченно.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time

KEY_BYTES = 32                 # 256-бит, base64 -> 43 символа
DIAG_MAX = 500                 # записей в кольце диагностики
DIAG_LINE_MAX = 300            # символов на запись (обрезаем всё, что длиннее)
STATS_FILE = "stats.json"
KEY_FILE = "relay.key"


class AuthKey:
    """Ключ релея. Генерируется один раз, хранится на volume.

    На диске — файл 0600 с base64-ключом и метаданными создания.
    В памяти — сам ключ (для сравнения hmac) и sha256 (для логов,
    чтобы ключ никогда не попадал в вывод целиком).
    """

    def __init__(self, value: str, created_at: float, generation: int):
        self.value = value
        self.created_at = created_at
        self.generation = generation
        raw = value.encode()
        self._raw = raw
        self.sha256 = hashlib.sha256(raw).hexdigest()

    def check(self, presented: str) -> bool:
        """Сравнение в постоянном времени (hmac.compare_digest)."""
        return hmac.compare_digest(self._raw, presented.encode())


def load_or_create_key(data_dir: str, log=print) -> tuple[AuthKey, bool]:
    """Возвращает (ключ, создан_ли_сейчас).

    Файл ключа создаётся атомарно (tempfile + rename), права 0600.
    Если файл повреждён — честная ошибка с путём, без тихой генерации
    нового (иначе клиент останется со старым ключом и будет загадочный
    отказ авторизации).
    """
    path = os.path.join(data_dir, KEY_FILE)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            key = AuthKey(str(doc["key"]), float(doc.get("created_at", 0)),
                          int(doc.get("generation", 1)))
        except Exception as e:
            raise RuntimeError(
                f"ключ повреждён ({path}): {e!r}. "
                f"Удалите файл и перезапустите контейнер — будет выпущен "
                f"новый (все клиенты нужно будет перенастроить).")
        return key, False

    try:
        os.makedirs(data_dir, exist_ok=True)
    except OSError as e:
        raise RuntimeError(_perm_hint(data_dir, e))
    value = secrets.token_urlsafe(KEY_BYTES)
    key = AuthKey(value, time.time(), 1)
    try:
        _write_key(path, key)
    except OSError as e:
        raise RuntimeError(_perm_hint(data_dir, e))
    return key, True


def _perm_hint(data_dir: str, e: BaseException) -> str:
    """Понятная подсказка вместо голого PermissionError.

    Частая причина: bind-mount ./data создан Docker'ом от root, а процесс
    в контейнере работает под relay (uid 10001) и не может писать.
    """
    who = f"{os.getuid()}/{os.getgid()}" if hasattr(os, "getuid") else "unknown"
    return (
        f"не удалось записать ключ в {data_dir}: {e!r}\n"
        f"  uid/gid процесса: {who}\n"
        f"  Чаще всего это права на каталог. Если используется bind-mount"
        f" (./data:/data), выполните на хосте:\n"
        f"      sudo chown -R 10001:10001 {os.path.abspath(data_dir)}\n"
        f"  Либо используйте именованный volume (так по умолчанию в"
        f" docker-compose.yml) — он наследует владельца из образа."
    )


def rotate_key(data_dir: str, old: AuthKey | None, log=print) -> AuthKey:
    """Перевыпуск. Старый ключ немедленно перестаёт действовать."""
    generation = (old.generation + 1) if old else 1
    value = secrets.token_urlsafe(KEY_BYTES)
    key = AuthKey(value, time.time(), generation)
    path = os.path.join(data_dir, KEY_FILE)
    _write_key(path, key)
    return key


def _write_key(path: str, key: AuthKey) -> None:
    doc = {"key": key.value, "created_at": key.created_at,
           "generation": key.generation}
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".key-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)          # атомарно: нет состояния «половина файла»
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------- статистика

class Stats:
    """Счётчики + персистентность в stats.json на volume.

    Пишем не чаще раз в STATS_FLUSH_SEC — на диск уходит один маленький
    JSON, потеря последних секунд счётчиков при краше допустима.
    """

    FIELDS = (
        "connections_total", "auth_ok", "auth_fail",
        "sessions_ok", "sessions_fail", "sessions_silent",
        "up_bytes", "down_bytes", "ws_frames_up", "ws_frames_down",
        "errors_upstream", "errors_client",
    )

    def __init__(self):
        for f in self.FIELDS:
            setattr(self, f, 0)
        self.started_at = time.time()
        self.active = 0
        self.peak_active = 0
        self._dirty = False

    def inc(self, field: str, n: int = 1):
        setattr(self, field, getattr(self, field) + n)
        self._dirty = True

    def conn_open(self):
        self.active += 1
        if self.active > self.peak_active:
            self.peak_active = self.active

    def conn_close(self):
        self.active = max(0, self.active - 1)

    def summary(self) -> dict:
        return {
            "uptime_sec": int(time.time() - self.started_at),
            "active": self.active,
            "peak_active": self.peak_active,
            **{f: getattr(self, f) for f in self.FIELDS},
        }

    # ---- персистентность

    def flush(self, data_dir: str) -> None:
        if not self._dirty:
            return
        path = os.path.join(data_dir, STATS_FILE)
        try:
            fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".stats-")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.summary(), f)
            os.replace(tmp, path)
            self._dirty = False
        except Exception:
            pass  # статистика не должна ронять сервер

    def load(self, data_dir: str) -> None:
        """Подхватываем накопленные счётчики после рестарта контейнера."""
        path = os.path.join(data_dir, STATS_FILE)
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            for f_ in self.FIELDS:
                if f_ in doc:
                    setattr(self, f_, int(doc[f_]))
        except FileNotFoundError:
            pass
        except Exception:
            pass  # битый stats.json — начинаем с нуля, не падаем


# ---------------------------------------------------------------- диагностика

class Diag:
    """Кольцо последних событий с причинами, для команды diag.

    Это единственное место, где мы храним текст событий, поэтому
    жёстко ограничено: DIAG_MAX записей, каждая <= DIAG_LINE_MAX символов.
    Пишется в файл diag.log (append, с обрезкой при превышении) — чтобы
    после краша контейнера последние события можно было прочитать.
    """

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.ring: collections.deque = collections.deque(maxlen=DIAG_MAX)

    def event(self, kind: str, detail: str = "") -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} {kind} {detail}"[:DIAG_LINE_MAX]
        self.ring.append(line)
        try:
            path = os.path.join(self.data_dir, "diag.log")
            # Ротация: если diag.log больше 512 КБ — переименовываем в .1
            # и начинаем новый. Максимум на диске ~1 МБ, навсегда.
            if os.path.exists(path) and os.path.getsize(path) > 512 * 1024:
                os.replace(path, path + ".1")
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass  # диагностика не должна ронять сервер

    def tail(self, n: int = 50) -> list:
        items = list(self.ring)
        return items[-n:]

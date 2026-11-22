#!/usr/bin/env python3
"""WSBridge Relay — WS-мост iPhone -> VDS -> Telegram kws по IPv6.

Протокол (контракт с приложением WSBridge):
  1. Клиент открывает WSS к /bridge (TLS терминирует nginx или сам сервер).
  2. Сервер отвечает 101 ВСЕМ (до проверки ключа) — пробинг видит рабочий WS.
  3. Первый кадр клиента: {"v":1,"token":"<key>"} (внутри TLS).
  4. Сервер: {"ok":true} либо close 1008 "unauthorized".
  5. Далее клиент шлёт ОРИГИНАЛЬНЫЙ 64-байтовый obfuscated2 init (формат
     tg-ws-proxy, без самодеятельных заголовков), сервер узнаёт DC/media,
     открывает TLS к kws{dc} по IPv6, WS-апгрейд /apiws, гонит MTProto
     кадрами в обе стороны.

Ресурсы: asyncio, один процесс, лимит соединений, idle-таймауты,
кольцо диагностики, статистика на volume. Зависимостей нет.

Запуск:  python3 relay.py --port 2087 --data-dir /data
CLI:     python3 relay.py key | key --rotate | stats | diag | doctor
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import signal
import ssl
import struct
import sys
import time

import mtproto
import state

log = logging.getLogger("wsb-relay")

# ---------------------------------------------------------------- настройки

DEFAULT_PORT = 2087
MAX_CONNECTIONS = 64          # жёсткий потолок (2-5 клиентов x ~12 сессий)
AUTH_TIMEOUT = 10.0           # сек на первый кадр с ключом
INIT_TIMEOUT = 15.0           # сек на 64-байтовый init
UPSTREAM_TIMEOUT = 10.0       # сек на TLS+WS к kws
IDLE_TIMEOUT = 600.0          # сек без трафика -> закрыть
READ_BUF = 65536
STATS_FLUSH_SEC = 30.0
HEALTH_FILE = "health"        # touch каждые 30с; healthcheck смотрит mtime

# IPv6 kws-гейтвеев (DoH 22.11.2026, проверены MTProto-обменом).
DEFAULT_DC6 = {
    1: "2001:b28:f23d:8005:7:0:109:337",
    2: "2001:67c:4e8:f004::9",
    3: "2001:b28:f23d:8005:7:0:109:337",
    4: "2001:67c:4e8:f004::9",
    5: "2001:b28:f23f:9::852:437",
    203: "2001:67c:4e8:f004::9",
}

# Коды ошибок для diag — каждое событие имеет машинно-читаемый kind.
E_AUTH_TIMEOUT = "auth_timeout"
E_AUTH_BAD = "auth_bad_token"
E_AUTH_FRAME = "auth_bad_frame"
E_INIT_TIMEOUT = "init_timeout"
E_INIT_BAD = "init_bad_proto"
E_UPSTREAM_TLS = "upstream_tls_fail"
E_UPSTREAM_WS = "upstream_ws_fail"
E_UPSTREAM_IDLE = "upstream_idle"
E_CLIENT_IDLE = "client_idle"
E_OVERSIZED = "packet_oversized"
E_LIMIT = "conn_limit"


# ---------------------------------------------------------------- WS-слой

class WSConn:
    """Минимальный WS поверх asyncio StreamReader/Writer.

    Только то, что нужно: masked binary frames, ping/pong, close.
    Без внешних зависимостей.
    """

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.r = reader
        self.w = writer
        self._frag = bytearray()
        self.closed = False

    async def send(self, payload: bytes, opcode: int = 0x2) -> None:
        self.w.write(mtproto.ws_frame(payload, opcode))
        await self.w.drain()

    async def send_text(self, text: str) -> None:
        await self.send(text.encode(), opcode=0x1)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.closed:
            return
        self.closed = True
        body = struct.pack(">H", code) + reason.encode()[:120]
        try:
            self.w.write(mtproto.ws_frame(body, opcode=0x8))
            await self.w.drain()
        except Exception:
            pass
        try:
            self.w.close()
        except Exception:
            pass

    async def recv(self):
        """Возвращает (opcode, payload) или None при CLOSE/EOF."""
        while True:
            hdr = await self.r.readexactly(2)
            fin = bool(hdr[0] & 0x80)
            op = hdr[0] & 0x0f
            ln = hdr[1] & 0x7f
            if ln == 126:
                ln = struct.unpack(">H", await self.r.readexactly(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", await self.r.readexactly(8))[0]
            if ln > mtproto.MAX_PACKET:
                raise ConnectionError("ws frame too large")
            masked = bool(hdr[1] & 0x80)
            mask = await self.r.readexactly(4) if masked else None
            data = await self.r.readexactly(ln) if ln else b""
            if mask:
                data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
            if op == 0x8:
                return None
            if op == 0x9:      # PING -> PONG
                await self.send(data, opcode=0xA)
                continue
            if op == 0xA:      # PONG
                continue
            if op in (0x0, 0x1, 0x2):
                if fin and not self._frag:
                    return op, data
                self._frag += data
                if len(self._frag) > mtproto.MAX_PACKET:
                    raise ConnectionError("ws message too large")
                if not fin:
                    continue
                out = bytes(self._frag)
                self._frag.clear()
                return op, out


async def accept_ws(reader: asyncio.StreamReader,
                    writer: asyncio.StreamWriter) -> WSConn | None:
    """HTTP Upgrade -> 101. Отвечаем 101 всем (ключ проверяется позже)."""
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not request_line:
            return None
        headers = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if line in (b"\r\n", b"\n", b""):
                break
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower()] = v.strip()
        if headers.get(b"upgrade", b"").lower() != b"websocket":
            # Не WS — ведём себя как обычный веб-сервер: 426.
            writer.write(b"HTTP/1.1 426 Upgrade Required\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return None
        key = headers.get(b"sec-websocket-key", b"")
        accept = base64.b64encode(
            __import__("hashlib").sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        ).decode()
        resp = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        writer.write(resp.encode())
        await writer.drain()
        return WSConn(reader, writer)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        return None


# ---------------------------------------------------------------- апстрим

async def upstream_connect(dc6: str, sni: str, path: str, insecure: bool):
    """TLS к kws по IPv6 + WS-апгрейд. Возвращает WSConn."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(dc6, 443, ssl=ctx, server_hostname=sni),
        timeout=UPSTREAM_TIMEOUT)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {sni}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\n"
        "\r\n"
    )
    writer.write(req.encode())
    await writer.drain()
    lines = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=UPSTREAM_TIMEOUT)
        if line in (b"\r\n", b"\n", b""):
            break
        lines.append(line.decode("latin1").strip())
    if not lines or "101" not in lines[0]:
        writer.close()
        raise ConnectionError(f"upstream upgrade: {lines[0] if lines else 'empty'}")
    return WSConn(reader, writer)


# ---------------------------------------------------------------- сессия

async def handle_client(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter,
                        key: state.AuthKey, stats: state.Stats,
                        diag: state.Diag, dc6map: dict,
                        insecure: bool, sem: asyncio.Semaphore):
    peer = writer.get_extra_info("peername")
    label = f"{peer[0]}:{peer[1]}" if peer else "?"
    stats.inc("connections_total")

    if sem.locked():
        stats.inc("errors_client")
        diag.event(E_LIMIT, f"{label} rejected: max {MAX_CONNECTIONS}")
        writer.close()
        return

    async with sem:
        stats.conn_open()
        ws = None
        up = None
        up_bytes = down_bytes = 0
        dc = None
        try:
            ws = await accept_ws(reader, writer)
            if ws is None:
                return

            # --- авторизация: первый кадр {"v":1,"token":...}
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=AUTH_TIMEOUT)
            except asyncio.TimeoutError:
                stats.inc("auth_fail")
                diag.event(E_AUTH_TIMEOUT, label)
                await ws.close(1008, "auth timeout")
                return
            if msg is None:
                return
            op, payload = msg
            try:
                doc = json.loads(payload.decode())
                token = str(doc.get("token", ""))
            except Exception:
                stats.inc("auth_fail")
                diag.event(E_AUTH_FRAME, f"{label} op={op} len={len(payload)}")
                await ws.close(1008, "bad auth frame")
                return
            if not key.check(token):
                stats.inc("auth_fail")
                diag.event(E_AUTH_BAD, label)
                await ws.close(1008, "unauthorized")
                return
            stats.inc("auth_ok")
            await ws.send_text('{"ok":true}')

            # --- init: оригинальный 64-байтовый obfuscated2
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=INIT_TIMEOUT)
            except asyncio.TimeoutError:
                diag.event(E_INIT_TIMEOUT, label)
                await ws.close(1008, "init timeout")
                return
            if msg is None:
                return
            op, init = msg
            parsed = mtproto.parse_init(init)
            if parsed is None:
                stats.inc("sessions_fail")
                diag.event(E_INIT_BAD, f"{label} len={len(init)}")
                await ws.close(1008, "bad init")
                return
            ckey, civ, proto, dc_idx = parsed
            is_media = dc_idx < 0
            abs_dc = abs(dc_idx)
            if abs_dc >= 10000:
                path = "/apiws_test"
                abs_dc -= 10000
            else:
                path = "/apiws"
            dc = abs_dc if abs_dc in dc6map else 2
            sni = f"kws{dc}{'-1' if is_media else ''}.web.telegram.org"
            dc6 = dc6map[dc]

            # --- апстрим
            try:
                up = await upstream_connect(dc6, sni, path, insecure)
            except ssl.SSLError as e:
                stats.inc("errors_upstream")
                diag.event(E_UPSTREAM_TLS, f"{label} DC{dc} {e}")
                await ws.close(1011, "upstream tls")
                return
            except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                stats.inc("errors_upstream")
                diag.event(E_UPSTREAM_WS, f"{label} DC{dc} {e!r}")
                await ws.close(1011, "upstream connect")
                return

            stats.inc("sessions_ok")
            log.info("open %s DC%d%s -> [%s] %s", label, dc,
                     " media" if is_media else "", dc6, sni)

            # init первым кадром апстриму
            await up.send(init)

            splitter = mtproto.Splitter(ckey, civ, proto)
            got_reply = asyncio.Event()

            async def client_to_up():
                nonlocal up_bytes
                try:
                    while True:
                        msg = await asyncio.wait_for(ws.recv(), timeout=IDLE_TIMEOUT)
                        if msg is None:
                            break
                        op, data = msg
                        if op != 0x2:
                            continue
                        up_bytes += len(data)
                        for pkt in splitter.feed(data):
                            await up.send(pkt)
                            stats.inc("ws_frames_up")
                        if splitter.oversized():
                            diag.event(E_OVERSIZED, label)
                            break
                except asyncio.TimeoutError:
                    diag.event(E_CLIENT_IDLE, label)
                except (ConnectionError, OSError, asyncio.IncompleteReadError):
                    pass
                finally:
                    await up.close()

            async def up_to_client():
                nonlocal down_bytes
                try:
                    while True:
                        msg = await asyncio.wait_for(up.recv(), timeout=IDLE_TIMEOUT)
                        if msg is None:
                            break
                        op, data = msg
                        down_bytes += len(data)
                        got_reply.set()
                        stats.inc("down_bytes", len(data))
                        stats.inc("ws_frames_down")
                        await ws.send(data)
                except asyncio.TimeoutError:
                    diag.event(E_UPSTREAM_IDLE, label)
                except (ConnectionError, OSError, asyncio.IncompleteReadError):
                    pass
                finally:
                    await ws.close()

            t1 = asyncio.create_task(client_to_up())
            t2 = asyncio.create_task(up_to_client())
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
            stats.inc("up_bytes", up_bytes)
            if not got_reply.is_set():
                stats.inc("sessions_silent")
            log.info("close %s DC%d up=%dB down=%dB reply=%s",
                     label, dc, up_bytes, down_bytes, got_reply.is_set())

        except (ConnectionError, OSError, asyncio.IncompleteReadError) as e:
            stats.inc("errors_client")
            diag.event("client_error", f"{label} {e!r}")
        except Exception as e:
            stats.inc("errors_client")
            diag.event("unexpected", f"{label} {e!r}")
            log.exception("unexpected error %s", label)
        finally:
            stats.conn_close()
            for c in (ws, up):
                if c is not None:
                    try:
                        await c.close()
                    except Exception:
                        pass


# ---------------------------------------------------------------- сервер

async def serve(args):
    data_dir = args.data_dir
    os.makedirs(data_dir, exist_ok=True)

    key, created = state.load_or_create_key(data_dir)
    stats = state.Stats()
    stats.load(data_dir)
    diag = state.Diag(data_dir)

    if created:
        # Ключ выводится ОДИН РАЗ при первом запуске.
        print("=" * 60)
        print("  WSBridge Relay — первый запуск")
        print(f"  Ключ авторизации (generation {key.generation}):")
        print(f"  {key.value}")
        print("  Сохраните его. Повторный вывод: relay.py key")
        print("=" * 60)
        diag.event("key_created", f"generation={key.generation}")
    else:
        log.info("key loaded (generation %d, sha256=%s…)",
                 key.generation, key.sha256[:12])

    dc6map = dict(DEFAULT_DC6)
    for item in args.dc6 or []:
        if "=" in item:
            k, v = item.split("=", 1)
            try:
                dc6map[int(k)] = v.strip()
            except ValueError:
                log.warning("bad --dc6 %r", item)

    sem = asyncio.Semaphore(MAX_CONNECTIONS)
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, key, stats, diag, dc6map,
                                   args.insecure, sem),
        args.host, args.port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info("listening on %s; max_conn=%d; DC6=%s", addrs, MAX_CONNECTIONS, dc6map)
    diag.event("server_start", f"port={args.port}")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    async def housekeeping():
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=STATS_FLUSH_SEC)
            except asyncio.TimeoutError:
                stats.flush(data_dir)
                # healthcheck: touch файла каждые 30с
                try:
                    with open(os.path.join(data_dir, HEALTH_FILE), "w") as f:
                        f.write(str(int(time.time())))
                except Exception:
                    pass
                log.info("stats: %s", stats.summary())

    hk = asyncio.create_task(housekeeping())
    await stop.wait()
    hk.cancel()
    server.close()
    await server.wait_closed()
    stats.flush(data_dir)
    diag.event("server_stop", "graceful")
    log.info("stopped: %s", stats.summary())


# ---------------------------------------------------------------- CLI

def cmd_key(args):
    key, _ = state.load_or_create_key(args.data_dir)
    if args.rotate:
        key = state.rotate_key(args.data_dir, key)
        print("Ключ перевыпущен. Старый больше не действует.")
    print(f"generation: {key.generation}")
    print(f"created:    {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(key.created_at))}")
    print(f"key:        {key.value}")
    print(f"sha256:     {key.sha256}")


def cmd_stats(args):
    s = state.Stats()
    s.load(args.data_dir)
    print(json.dumps(s.summary(), indent=2, ensure_ascii=False))


def cmd_diag(args):
    d = state.Diag(args.data_dir)
    # читаем файл (кольцо в памяти пусто в CLI-процессе)
    path = os.path.join(args.data_dir, "diag.log")
    lines = []
    for p in (path + ".1", path):
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                lines += f.read().splitlines()
    for line in lines[-args.n:]:
        print(line)


def cmd_doctor(args):
    """Самопроверка: ключ, IPv6, DNS, порт."""
    import socket
    print("=== WSBridge Relay doctor ===")
    ok = True
    # ключ
    try:
        key, _ = state.load_or_create_key(args.data_dir)
        print(f"[ok] key generation={key.generation}")
    except Exception as e:
        print(f"[FAIL] key: {e}")
        ok = False
    # IPv6
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("2001:67c:4e8:f004::9", 443))
        s.close()
        print("[ok] IPv6 connect to kws2")
    except Exception as e:
        print(f"[FAIL] IPv6: {e}")
        ok = False
    # DNS
    try:
        socket.getaddrinfo("kws2.web.telegram.org", 443)
        print("[ok] DNS kws2.web.telegram.org")
    except Exception as e:
        print(f"[FAIL] DNS: {e}")
        ok = False
    print("=== " + ("ALL OK" if ok else "PROBLEMS FOUND") + " ===")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description="WSBridge Relay")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--data-dir", default="/data")
    ap.add_argument("--dc6", action="append", default=[])
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    p_key = sub.add_parser("key")
    p_key.add_argument("--rotate", action="store_true")
    sub.add_parser("stats")
    p_diag = sub.add_parser("diag")
    p_diag.add_argument("-n", type=int, default=50)
    sub.add_parser("doctor")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)

    if args.cmd == "key":
        cmd_key(args)
    elif args.cmd == "stats":
        cmd_stats(args)
    elif args.cmd == "diag":
        cmd_diag(args)
    elif args.cmd == "doctor":
        cmd_doctor(args)
    else:
        asyncio.run(serve(args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

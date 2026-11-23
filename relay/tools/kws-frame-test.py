"""Диагностика: какой способ отправки init принимает kws-гейтвей.

Запускается НА VDS (нужен исходящий IPv6). Телефон не нужен.

Спор, который решает скрипт:
  вариант A — init и первый MTProto-пакет в ОДНОМ WS-кадре
  вариант B — init отдельным кадром, пакет следующим

Релей сейчас делает B и получает down=0B (sessions_silent).
Ранний ручной тест делал A и получил ответ 103 B. Скрипт проверяет
оба варианта на реальном kws и печатает, какой отвечает.

Запуск:  python3 tools/kws-frame-test.py
"""

import asyncio
import base64
import os
import socket
import ssl
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

import mtproto  # noqa: E402

DC6 = {
    1: "2001:b28:f23d:8005:7:0:109:337",
    2: "2001:67c:4e8:f004::9",
    4: "2001:67c:4e8:f004::9",
    5: "2001:b28:f23f:9::852:437",
}
DC = 2
SNI = f"kws{DC}.web.telegram.org"
DC6 = DC6[DC]
PATH = "/apiws"
WAIT = 12.0


def build_init_and_packet(dc: int):
    """Настоящий obfuscated2 init + req_pq_multi, как шлёт Telegram.

    Использует mtproto.AESCTR (stdlib) — работает в alpine-контейнере
    без cryptography.
    """
    init = bytearray(os.urandom(64))
    key, iv = bytes(init[8:40]), bytes(init[40:56])
    dec = mtproto.AESCTR(key, iv)
    plain = bytearray(dec.crypt(bytes(init)))
    plain[56:60] = b"\xef\xef\xef\xef"          # abridged
    struct.pack_into("<h", plain, 60, dc)
    enc0 = mtproto.AESCTR(key, iv)
    init = bytes(enc0.crypt(bytes(plain)))

    enc = mtproto.AESCTR(key, iv)
    enc.skip(64)                                 # пропустить init
    body = bytearray(20)
    struct.pack_into("<I", body, 0, 0xBE7E8EF1)  # req_pq_multi
    body[4:20] = os.urandom(16)
    msg = bytearray(40)
    struct.pack_into("<Q", msg, 0, 0)            # auth_key_id = 0
    now = __import__("time").time()
    msg_id = int(now) * 4294967296 + int((now % 1) * 4294967296)
    msg_id = (msg_id & ~3) | 0                   # выровнять на 4
    struct.pack_into("<Q", msg, 8, msg_id)
    struct.pack_into("<I", msg, 16, len(body))
    msg[20:40] = body
    framed = bytes([len(msg) // 4]) + bytes(msg)
    ct = enc.crypt(framed)
    return init, ct


async def connect_upstream():
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(DC6, 443, ssl=ctx, server_hostname=SNI),
        timeout=10)
    wskey = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {PATH} HTTP/1.1\r\n"
        f"Host: {SNI}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {wskey}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\n\r\n"
    )
    writer.write(req.encode())
    await writer.drain()
    lines = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=10)
        if line in (b"\r\n", b"\n", b""):
            break
        lines.append(line.decode("latin1").strip())
    if not lines or "101" not in lines[0]:
        raise RuntimeError(f"upgrade failed: {lines[0] if lines else 'empty'}")
    return reader, writer


async def read_frame(reader):
    hdr = await reader.readexactly(2)
    op = hdr[0] & 0x0F
    ln = hdr[1] & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", await reader.readexactly(2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", await reader.readexactly(8))[0]
    masked = bool(hdr[1] & 0x80)
    mask = await reader.readexactly(4) if masked else b""
    data = await reader.readexactly(ln) if ln else b""
    if masked:
        data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
    return op, data


async def try_variant(name: str, combined: bool):
    init, pkt = build_init_and_packet(DC)
    try:
        reader, writer = await connect_upstream()
    except Exception as e:
        print(f"[{name}] upstream connect FAILED: {e!r}")
        return False
    try:
        if combined:
            writer.write(mtproto.ws_frame(init + pkt))
        else:
            writer.write(mtproto.ws_frame(init))
            writer.write(mtproto.ws_frame(pkt))
        await writer.drain()
        op, data = await asyncio.wait_for(read_frame(reader), timeout=WAIT)
        if op == 0x8:
            code = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else -1
            print(f"[{name}] CLOSE code={code} reason={data[2:24]!r}")
            return False
        print(f"[{name}] REPLY op={op} len={len(data)} head={data[:12].hex()}")
        return True
    except asyncio.TimeoutError:
        print(f"[{name}] TIMEOUT {WAIT}s — kws молчит")
        return False
    except Exception as e:
        print(f"[{name}] ERROR {e!r}")
        return False
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    print(f"target: [{DC6}]:443  SNI={SNI}  path={PATH}  DC={DC}")
    print()
    a = await try_variant("A init+packet в ОДНОМ кадре", combined=True)
    await asyncio.sleep(1)
    b = await try_variant("B init и пакет ОТДЕЛЬНО", combined=False)
    print()
    print("=" * 56)
    if a and not b:
        print("ВЫВОД: kws требует init+первый пакет ОДНИМ кадром.")
        print("       Релей нужно править: склеивать init с первым пакетом.")
    elif b and not a:
        print("ВЫВОД: раздельные кадры работают, A нет. Релей правилен,")
        print("       причину молчания ищем в другом.")
    elif a and b:
        print("ВЫВОД: оба варианта работают. Причина молчания НЕ в")
        print("       кадрировании — смотрим на сторону клиента/тайминги.")
    else:
        print("ВЫВОД: оба варианта молчат. kws не отвечает этому init")
        print("       с данного адреса — проблема не в кадрировании.")
    print("=" * 56)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

#!/usr/bin/env python3
"""
WSBridge WS-мост для VPS: iPhone -> VPS (сырой TCP) -> TLS+WS -> kws-гейтвей Telegram по IPv6.

Зачем: IPv4-диапазоны Telegram фильтруются (и в РФ, и с CF-воркеров), а kws-гейтвеи
по IPv6 живые — проверено реальным MTProto req_pq_multi для DC1..DC5 (ответ 103 B).

Протокол со стороны iPhone НЕ меняется (WSClient.connectRelay):
    iPhone -> мост:  "wsb1 <IPv4-DC>\n" + сырой obfuscated2-поток
    мост -> Telegram: TLS к kws{dc} по IPv6, WS-апгрейд /apiws
                      (Sec-WebSocket-Protocol: binary обязателен, иначе 404),
                      дальше каждый MTProto-пакет = отдельный WS-кадр.

Мост сам режет поток на MTProto-пакеты: для этого он читает 64-байтовый init,
достаёт key/iv/proto_tag/dc_idx и расшифровывает ТОЛЬКО префиксы длин
(как MsgSplitter в приложении). Payload не изменяется.

Зависимости: только стандартная библиотека Python 3.9+.
Запуск:  python3 wsb-ws-bridge.py --port 8443
Docker:  см. Dockerfile рядом (образ ~55 МБ, alpine).
"""

import argparse
import asyncio
import base64
import ipaddress
import logging
import os
import re
import signal
import ssl
import struct
import sys

SECRET = b"wsb1"
HEAD_RE = re.compile(rb"^wsb1 (\d{1,3}(?:\.\d{1,3}){3})\n")
MAX_HEAD = 64

HANDSHAKE_LEN = 64
PROTO_ABRIDGED = 0xEFEFEFEF
PROTO_INTERMEDIATE = 0xEEEEEEEE
PROTO_PADDED = 0xDDDDDDDD
VALID_PROTOS = {PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED}

# Канонические IPv4 DC -> номер DC (совпадает с TunnelSession.canonicalIPs).
CANONICAL = {
    "149.154.175.50": 1,
    "149.154.167.220": 2,
    "149.154.175.100": 3,
    "149.154.167.91": 4,
    "91.108.56.130": 5,
}
# Дополнительные DC-адреса, которые Telegram реально использует (из журналов).
EXTRA_DC = {
    "149.154.167.35": 2,
    "149.154.167.41": 2,
    "149.154.167.51": 2,
    "149.154.167.255": 2,
    "149.154.171.255": 5,
    "149.154.171.5": 5,
    "91.105.192.100": 203,
}

# IPv6 kws-гейтвеев: получены через DoH (dns.google) 22.11.2026 и проверены
# реальным MTProto-обменом. Можно переопределить через --dc6 "2=addr" и т.п.
DEFAULT_DC6 = {
    1: "2001:b28:f23d:8005:7:0:109:337",
    2: "2001:67c:4e8:f004::9",
    3: "2001:b28:f23d:8005:7:0:109:337",
    4: "2001:67c:4e8:f004::9",
    5: "2001:b28:f23f:9::852:437",
    203: "2001:67c:4e8:f004::9",
}

DIAL_TIMEOUT = 10.0
IDLE_TIMEOUT = 600.0
BUF = 65536
MAX_FRAME = 16 * 1024 * 1024

log = logging.getLogger("wsb-bridge")


# ---------------------------------------------------------------- AES-CTR
# Чистый Python AES нужен только для чтения длин MTProto-пакетов.
# Реализация компактная, без зависимостей; скорость не критична, т.к.
# расшифровываются лишь 1-4 байта префикса каждого пакета.

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def _xtime(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


def _expand_key(key):
    nk, nr = 8, 14
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk, 4*(nr+1)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i//nk - 1]
        elif i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i-nk][j] ^ t[j] for j in range(4)])
    return w


def _encrypt_block(w, block):
    nr = 14
    s = [list(block[i::4]) for i in range(4)]  # state[row][col]

    def add_round_key(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[rnd*4+c][r]

    add_round_key(0)
    for rnd in range(1, nr+1):
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        if rnd != nr:
            for c in range(4):
                a = [s[r][c] for r in range(4)]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                for r in range(4):
                    s[r][c] = a[r] ^ t ^ _xtime(a[r] ^ a[(r+1) % 4])
        add_round_key(rnd)
    return bytes(s[r][c] for c in range(4) for r in range(4))


class AESCTR:
    """AES-256-CTR с произвольным начальным counter; умеет fast-forward."""

    def __init__(self, key: bytes, iv: bytes):
        self._w = _expand_key(key)
        self._ctr = int.from_bytes(iv, "big")
        self._buf = b""

    def _keystream(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            if not self._buf:
                block = self._ctr.to_bytes(16, "big")
                self._buf = _encrypt_block(self._w, block)
                self._ctr = (self._ctr + 1) & ((1 << 128) - 1)
            take = min(n - len(out), len(self._buf))
            out += self._buf[:take]
            self._buf = self._buf[take:]
        return bytes(out)

    def skip(self, n: int):
        """Продвигает keystream на n байт, выравнивание не требуется."""
        # Добираем из уже сгенерированного остатка блока...
        if self._buf:
            take = min(n, len(self._buf))
            self._buf = self._buf[take:]
            n -= take
        # ...затем генерируем недостающее ЦЕЛИКОМ (без арифметики по _ctr,
        # которая не учитывала бы частичный блок в _buf).
        if n > 0:
            self._keystream(n)

    def crypt(self, data: bytes) -> bytes:
        ks = self._keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))


# ---------------------------------------------------------------- WS framing

def ws_frame(payload: bytes, opcode: int = 0x2) -> bytes:
    """Клиентский (masked) WS-кадр."""
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    if n < 126:
        hdr = bytes([0x80 | opcode, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", n)
    else:
        hdr = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", n)
    return hdr + mask + masked


class WSReader:
    """Читает WS-кадры из StreamReader, отдаёт payload binary-сообщений."""

    def __init__(self, reader: asyncio.StreamReader):
        self.r = reader
        self._frag = bytearray()

    async def next_payload(self):
        while True:
            hdr = await self.r.readexactly(2)
            fin = bool(hdr[0] & 0x80)
            op = hdr[0] & 0x0f
            ln = hdr[1] & 0x7f
            if ln == 126:
                ln = struct.unpack(">H", await self.r.readexactly(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", await self.r.readexactly(8))[0]
            if ln > MAX_FRAME:
                raise ConnectionError("ws frame too large")
            masked = bool(hdr[1] & 0x80)
            mask = await self.r.readexactly(4) if masked else None
            data = await self.r.readexactly(ln) if ln else b""
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if op == 0x8:  # CLOSE
                code = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else 0
                reason = data[2:].decode("utf-8", "replace")
                log.info("upstream CLOSE code=%s reason=%r", code, reason)
                return None
            if op == 0x9:  # PING -> PONG handled by caller via writer
                continue
            if op == 0xa:
                continue
            if op in (0x0, 0x1, 0x2):
                if fin and not self._frag:
                    return data
                self._frag += data
                if not fin:
                    continue
                out = bytes(self._frag)
                self._frag.clear()
                return out


# ---------------------------------------------------------------- MTProto split

class Splitter:
    """Режет сырой поток клиента на MTProto-пакеты, читая только префиксы длин.

    Ровно та же логика, что MsgSplitter в приложении: payload не меняется,
    каждый пакет уходит отдельным WS-кадром.
    """

    def __init__(self, key: bytes, iv: bytes, proto: int):
        self.cipher = AESCTR(key, iv)
        self.cipher.skip(HANDSHAKE_LEN)
        self.proto = proto
        self.buf = bytearray()
        self._plain = bytearray()
        self.disabled = False

    def feed(self, data: bytes):
        """Как MsgSplitter.split в приложении: payload не меняется,
        пакет целиком уходит в отдельный WS-кадр."""
        if not data:
            return []
        if self.disabled:
            return [bytes(data)]
        self.buf += data
        self._plain += self.cipher.crypt(data)
        out = []
        offset = 0
        n = len(self.buf)
        while offset < n:
            pkt = self._next_len(offset, n - offset)
            if pkt is None:
                break
            if pkt <= 0:
                # неизвестный протокол/нулевой пакет: остаток одним куском
                out.append(bytes(self.buf[offset:]))
                offset = n
                self.disabled = True
                break
            if offset + pkt > n:
                break
            out.append(bytes(self.buf[offset:offset + pkt]))
            offset += pkt
        if offset:
            del self.buf[:offset]
            del self._plain[:offset]
        return out

    def _next_len(self, offset: int, avail: int):
        if avail <= 0:
            return None
        if self.proto == PROTO_ABRIDGED:
            first = self._plain[offset]
            if first in (0x7f, 0xff):
                if avail < 4:
                    return None
                payload = (self._plain[offset + 1] |
                           (self._plain[offset + 2] << 8) |
                           (self._plain[offset + 3] << 16)) * 4
                hdr = 4
            else:
                payload = (first & 0x7f) * 4
                hdr = 1
            if payload <= 0:
                return 0
            total = hdr + payload
            return total if avail >= total else None
        if self.proto in (PROTO_INTERMEDIATE, PROTO_PADDED):
            if avail < 4:
                return None
            payload = int.from_bytes(bytes(self._plain[offset:offset + 4]),
                                     "little") & 0x7fffffff
            if payload <= 0:
                return 0
            total = 4 + payload
            return total if avail >= total else None
        return 0

    def flush(self):
        if not self.buf:
            return []
        tail = bytes(self.buf)
        self.buf.clear()
        self._plain.clear()
        return [tail]


def parse_init(init: bytes):
    """Достаёт key/iv/proto/dc из 64-байтового obfuscated2 init."""
    if len(init) != HANDSHAKE_LEN:
        return None
    key, iv = init[8:40], init[40:56]
    dec = AESCTR(key, iv)
    plain = dec.crypt(init)
    proto = struct.unpack("<I", plain[56:60])[0]
    if proto not in VALID_PROTOS:
        return None
    dc_idx = struct.unpack("<h", plain[60:62])[0]
    return key, iv, proto, dc_idx


# ---------------------------------------------------------------- bridge

async def ws_connect(dc6: str, sni: str, path: str):
    """TLS к IPv6 kws + WS-апгрейд. Возвращает (reader, writer, WSReader)."""
    ctx = ssl.create_default_context()
    # Сертификат kws выписан на *.web.telegram.org; проверяем цепочку и имя.
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(dc6, 443, ssl=ctx, server_hostname=sni),
        timeout=DIAL_TIMEOUT)
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
        line = await asyncio.wait_for(reader.readline(), timeout=DIAL_TIMEOUT)
        if line in (b"\r\n", b"\n", b""):
            break
        lines.append(line.decode("latin1").strip())
    if not lines or "101" not in lines[0]:
        writer.close()
        raise ConnectionError(f"ws upgrade failed: {lines[0] if lines else 'empty'}")
    return reader, writer, WSReader(reader)


async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter,
                 dc6map: dict, stats: dict):
    peer = cw.get_extra_info("peername")
    uw = None
    up = down = 0
    dc = None
    try:
        head = b""
        while b"\n" not in head:
            ch = await asyncio.wait_for(cr.read(1), timeout=10.0)
            if not ch:
                return
            head += ch
            if len(head) > MAX_HEAD:
                return
        m = HEAD_RE.match(head)
        if not m:
            log.warning("bad head from %s: %r", peer, head[:32])
            return
        dst = m.group(1).decode()
        dc = CANONICAL.get(dst) or EXTRA_DC.get(dst)
        if dc is None:
            # неизвестный IP: пробуем угадать по подсети
            if dst.startswith("149.154.175."):
                dc = 1
            elif dst.startswith("149.154.167."):
                dc = 2
            elif dst.startswith("149.154.171."):
                dc = 5
            elif dst.startswith("91.108.56."):
                dc = 5
            elif dst.startswith("91.105.192."):
                dc = 203
            else:
                dc = 2
        dc6 = dc6map.get(dc)
        if not dc6:
            log.warning("no IPv6 for DC%s (dst=%s)", dc, dst)
            stats["no_dc6"] += 1
            return

        # init от клиента: 64 байта
        init = await asyncio.wait_for(cr.readexactly(HANDSHAKE_LEN), timeout=15.0)
        parsed = parse_init(init)
        if parsed is None:
            log.warning("bad init from %s", peer)
            stats["bad_init"] += 1
            return
        key, iv, proto, dc_idx = parsed
        is_media = dc_idx < 0
        abs_dc = abs(dc_idx)
        if abs_dc >= 10000:
            path = "/apiws_test"
            abs_dc -= 10000
        else:
            path = "/apiws"
        real_dc = abs_dc if abs_dc in dc6map else dc
        sni = f"kws{real_dc}{'-1' if is_media else ''}.web.telegram.org"
        dc6 = dc6map.get(real_dc, dc6)

        ur, uw, wsr = await ws_connect(dc6, sni, path)
        stats["ok"] += 1
        log.info("open %s dst=%s DC%s%s -> [%s] %s", peer, dst, real_dc,
                 " media" if is_media else "", dc6, sni)

        # init первым кадром
        uw.write(ws_frame(init))
        await uw.drain()

        splitter = Splitter(key, iv, proto)
        got_reply = asyncio.Event()

        async def client_to_ws():
            nonlocal up
            try:
                while True:
                    data = await asyncio.wait_for(cr.read(BUF), timeout=IDLE_TIMEOUT)
                    if not data:
                        break
                    up += len(data)
                    for pkt in splitter.feed(data):
                        uw.write(ws_frame(pkt))
                    await uw.drain()
            except (asyncio.TimeoutError, ConnectionError, OSError,
                    asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    uw.close()
                except Exception:
                    pass

        async def ws_to_client():
            nonlocal down
            try:
                while True:
                    payload = await asyncio.wait_for(wsr.next_payload(),
                                                     timeout=IDLE_TIMEOUT)
                    if payload is None:
                        break
                    down += len(payload)
                    got_reply.set()
                    cw.write(payload)
                    await cw.drain()
            except (asyncio.TimeoutError, ConnectionError, OSError,
                    asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    cw.close()
                except Exception:
                    pass

        t1 = asyncio.create_task(client_to_ws())
        t2 = asyncio.create_task(ws_to_client())
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in (t1, t2):
            if not t.done():
                t.cancel()
        stats["up"] += up
        stats["down"] += down
        if not got_reply.is_set():
            stats["silent"] += 1
        log.info("close %s DC%s up=%dB down=%dB reply=%s",
                 peer, real_dc, up, down, got_reply.is_set())
    except (asyncio.TimeoutError, ConnectionError, OSError,
            asyncio.IncompleteReadError, ssl.SSLError) as e:
        stats["err"] += 1
        log.warning("fail %s DC%s: %s", peer, dc, e)
    finally:
        for w in (cw, uw):
            if w is not None:
                try:
                    w.close()
                except Exception:
                    pass
        stats["total"] += 1


async def main():
    ap = argparse.ArgumentParser(description="WSBridge WS bridge (IPv6 kws)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--dc6", action="append", default=[],
                    help='переопределить IPv6: "2=2001:67c:4e8:f004::9"')
    ap.add_argument("--insecure", action="store_true",
                    help="не проверять сертификат kws (для отладки)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)

    dc6map = dict(DEFAULT_DC6)
    for item in args.dc6:
        if "=" in item:
            k, v = item.split("=", 1)
            try:
                dc6map[int(k)] = v.strip()
            except ValueError:
                log.warning("bad --dc6 %r", item)

    if args.insecure:
        global ssl
        _orig = ssl.create_default_context

        def _insecure(*a, **kw):
            c = _orig(*a, **kw)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            return c
        ssl.create_default_context = _insecure

    stats = {"total": 0, "ok": 0, "err": 0, "silent": 0,
             "bad_init": 0, "no_dc6": 0, "up": 0, "down": 0}

    server = await asyncio.start_server(
        lambda r, w: handle(r, w, dc6map, stats), args.host, args.port)
    log.info("listening on %s; DC6=%s",
             ", ".join(str(s.getsockname()) for s in server.sockets), dc6map)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    async def reporter():
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=60.0)
            except asyncio.TimeoutError:
                log.info("stats: %s", stats)

    rep = asyncio.create_task(reporter())
    await stop.wait()
    rep.cancel()
    server.close()
    await server.wait_closed()
    log.info("stopped: %s", stats)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

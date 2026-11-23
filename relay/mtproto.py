"""Криптография и разбор MTProto для WSBridge Relay.

Только стандартная библиотека: AES-256-CTR реализован здесь, чтобы образ
не тянул cryptography (~15 МБ wheels + libssl). Расшифровываются ЛИШЬ
префиксы длин пакетов и 64-байтовый init — нагрузка на CPU минимальна.

Проверено против cryptography: skip на 0/1/17/64/70/1000 + чередование,
сплиттер байт-в-байт для abridged (включая 0x7f extended) / intermediate /
padded, целиком, кусками и побайтово.
"""

from __future__ import annotations

import os
import struct

HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_ABRIDGED = 0xEFEFEFEF
PROTO_INTERMEDIATE = 0xEEEEEEEE
PROTO_PADDED = 0xDDDDDDDD
VALID_PROTOS = (PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED)

MAX_PACKET = 16 * 1024 * 1024

_SBOX = bytes((
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
))
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

# Таблица умножения на 2 в GF(2^8) — считается один раз на процесс.
_XTIME = bytes(((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1
               for a in range(256))


def _expand_key(key: bytes) -> list:
    """Key schedule AES-256 (14 раундов). Вызывается раз на соединение."""
    nk, nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w


def _encrypt_block(w: list, block: bytes) -> bytes:
    s = [list(block[i::4]) for i in range(4)]

    def add_round_key(rnd):
        for c in range(4):
            col = w[rnd * 4 + c]
            for r in range(4):
                s[r][c] ^= col[r]

    add_round_key(0)
    for rnd in range(1, 15):
        for r in range(4):
            row = s[r]
            for c in range(4):
                row[c] = _SBOX[row[c]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        if rnd != 14:
            for c in range(4):
                a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
                t = a0 ^ a1 ^ a2 ^ a3
                s[0][c] = a0 ^ t ^ _XTIME[a0 ^ a1]
                s[1][c] = a1 ^ t ^ _XTIME[a1 ^ a2]
                s[2][c] = a2 ^ t ^ _XTIME[a2 ^ a3]
                s[3][c] = a3 ^ t ^ _XTIME[a3 ^ a0]
        add_round_key(rnd)
    return bytes(s[r][c] for c in range(4) for r in range(4))


class AESCTR:
    """AES-256-CTR c произвольным начальным counter и fast-forward.

    Память: один блок keystream (16 Б) + key schedule. Никаких буферов
    на весь поток — важно для лимита памяти контейнера.
    """

    __slots__ = ("_w", "_ctr", "_buf")
    _MASK = (1 << 128) - 1

    def __init__(self, key: bytes, iv: bytes):
        self._w = _expand_key(key)
        self._ctr = int.from_bytes(iv, "big")
        self._buf = b""

    def _keystream(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            if not self._buf:
                self._buf = _encrypt_block(self._w, self._ctr.to_bytes(16, "big"))
                self._ctr = (self._ctr + 1) & self._MASK
            take = min(n - len(out), len(self._buf))
            out += self._buf[:take]
            self._buf = self._buf[take:]
        return bytes(out)

    def skip(self, n: int) -> None:
        if self._buf:
            take = min(n, len(self._buf))
            self._buf = self._buf[take:]
            n -= take
        if n > 0:
            self._keystream(n)

    def crypt(self, data: bytes) -> bytes:
        ks = self._keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))


def parse_init(init: bytes):
    """Достаёт (key, iv, proto, dc_idx) из 64-байтового obfuscated2 init.

    Формат — оригинальный tg-ws-proxy: клиент шлёт свой init как есть.
    Возвращает None, если proto_tag невалиден (это не MTProto-клиент).
    """
    if len(init) != HANDSHAKE_LEN:
        return None
    key = init[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    iv = init[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    plain = AESCTR(key, iv).crypt(init)
    proto = struct.unpack_from("<I", plain, PROTO_TAG_POS)[0]
    if proto not in VALID_PROTOS:
        return None
    dc_idx = struct.unpack_from("<h", plain, DC_IDX_POS)[0]
    return key, iv, proto, dc_idx


class Splitter:
    """Режет шифрпоток клиента на MTProto-пакеты для отдельных WS-кадров.

    Расшифровывает только префиксы длин; payload уходит как есть.
    Память ограничена: буфер не может вырасти больше MAX_PACKET, иначе
    соединение считается битым и закрывается (защита от OOM).
    """

    __slots__ = ("cipher", "proto", "buf", "_plain", "disabled")

    def __init__(self, key: bytes, iv: bytes, proto: int):
        self.cipher = AESCTR(key, iv)
        self.cipher.skip(HANDSHAKE_LEN)
        self.proto = proto
        self.buf = bytearray()
        self._plain = bytearray()
        self.disabled = False

    def feed(self, data: bytes) -> list:
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

    def oversized(self) -> bool:
        return len(self.buf) > MAX_PACKET

    def _next_len(self, offset: int, avail: int):
        if avail <= 0:
            return None
        if self.proto == PROTO_ABRIDGED:
            first = self._plain[offset]
            if first in (0x7f, 0xff):
                if avail < 4:
                    return None
                payload = (self._plain[offset + 1]
                           | (self._plain[offset + 2] << 8)
                           | (self._plain[offset + 3] << 16)) * 4
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
            payload = int.from_bytes(
                bytes(self._plain[offset:offset + 4]), "little") & 0x7fffffff
            if payload <= 0:
                return 0
            total = 4 + payload
            return total if avail >= total else None
        return 0

    def flush(self) -> list:
        if not self.buf:
            return []
        tail = bytes(self.buf)
        self.buf.clear()
        self._plain.clear()
        return [tail]


def ws_frame(payload: bytes, opcode: int = 0x2, mask: bool = True) -> bytes:
    """WS-кадр. mask=True — клиентский (обязателен по RFC 6455),
    mask=False — серверный (сервер НЕ маскирует; masked-кадр от сервера
    клиент обязан отклонить как нарушение протокола)."""
    n = len(payload)
    flag = 0x80 if mask else 0x00
    if n < 126:
        hdr = bytes([0x80 | opcode, flag | n])
    elif n < 65536:
        hdr = bytes([0x80 | opcode, flag | 126]) + struct.pack(">H", n)
    else:
        hdr = bytes([0x80 | opcode, flag | 127]) + struct.pack(">Q", n)
    if not mask:
        return hdr + payload
    m = os.urandom(4)
    masked = bytes(b ^ m[i & 3] for i, b in enumerate(payload))
    return hdr + m + masked

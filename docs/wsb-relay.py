#!/usr/bin/env python3
"""
WSBridge relay — сырой TCP-прокси для режима «CF Worker» с адресом host:port.

Протокол (совпадает с WSClient.connectRelay в Tunnel/WSClient.swift):
  клиент -> реле:  "wsb1 <dst-IPv4>\n"  затем сырые байты MTProto
  реле -> DC:      открывает TCP dst:443 и гонит байты в обе стороны без изменений

Никакого TLS/WS/HTTP: реле видит только obfuscated2-поток Telegram.
Запуск:  python3 wsb-relay.py --port 8443
Проверка: nc <vps> 8443  -> отправить "wsb1 149.154.167.220\n" и смотреть ответ.

Зависимостей нет, только стандартная библиотека Python 3.8+.
"""

import argparse
import asyncio
import ipaddress
import logging
import re
import signal
import sys

SECRET = b"wsb1"
HEAD_RE = re.compile(rb"^wsb1 (\d{1,3}(?:\.\d{1,3}){3})\n")
MAX_HEAD = 64          # "wsb1 " + IPv4 + "\n" заведомо меньше
DIAL_TIMEOUT = 8.0     # сек на TCP-коннект к DC
IDLE_TIMEOUT = 300.0   # сек без трафика в обе стороны -> закрыть
BUF = 65536

log = logging.getLogger("wsb-relay")


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
               label: str, on_first=None):
    """Гонит байты reader -> writer, пока одна из сторон не закроется."""
    total = 0
    try:
        while True:
            data = await asyncio.wait_for(reader.read(BUF), timeout=IDLE_TIMEOUT)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            total += len(data)
            if on_first is not None:
                on_first()
                on_first = None
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
    return total


async def handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter,
                 stats: dict):
    peer = client_w.get_extra_info("peername")
    dst = None
    up = down = 0
    try:
        # 1. Заголовок "wsb1 <ip>\n". Клиент может прислать его вместе с
        #    первыми байтами MTProto — читаем аккуратно, не теряя хвост.
        head = b""
        while b"\n" not in head:
            chunk = await asyncio.wait_for(client_r.read(1), timeout=10.0)
            if not chunk:
                return
            head += chunk
            if len(head) > MAX_HEAD:
                log.warning("head too long from %s", peer)
                return
        m = HEAD_RE.match(head)
        if not m:
            log.warning("bad head from %s: %r", peer, head[:32])
            return
        dst = m.group(1).decode()
        try:
            ipaddress.IPv4Address(dst)
        except ValueError:
            log.warning("bad dst from %s: %s", peer, dst)
            return

        # 2. TCP к DC:443.
        try:
            dc_r, dc_w = await asyncio.wait_for(
                asyncio.open_connection(dst, 443), timeout=DIAL_TIMEOUT)
        except (asyncio.TimeoutError, OSError) as e:
            log.warning("dial %s failed: %s", dst, e)
            stats["dial_fail"] += 1
            return

        stats["ok"] += 1
        log.info("open %s -> %s:443", peer, dst)

        # 3. Две трубы. Первый байт от DC = признак живого канала.
        got_reply = asyncio.Event()

        def mark():
            got_reply.set()

        t_up = asyncio.create_task(pipe(client_r, dc_w, "up"))
        t_down = asyncio.create_task(pipe(dc_r, client_w, "down", on_first=mark))
        done, pending = await asyncio.wait(
            [t_up, t_down], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        up = t_up.result() if t_up in done else 0
        down = t_down.result() if t_down in done else 0
        stats["up"] += up
        stats["down"] += down
        if not got_reply.is_set():
            stats["silent"] += 1
        log.info("close %s -> %s up=%dB down=%dB reply=%s",
                 peer, dst, up, down, got_reply.is_set())
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            client_w.close()
        except Exception:
            pass
        stats["total"] += 1


async def main():
    ap = argparse.ArgumentParser(description="WSBridge raw TCP relay")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout)

    stats = {"total": 0, "ok": 0, "dial_fail": 0, "silent": 0, "up": 0, "down": 0}

    server = await asyncio.start_server(
        lambda r, w: handle(r, w, stats), args.host, args.port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info("listening on %s (secret=%s)", addrs, SECRET.decode())

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
                log.info("stats: total=%(total)d ok=%(ok)d dial_fail=%(dial_fail)d "
                         "silent=%(silent)d up=%(up)dB down=%(down)dB", stats)

    rep = asyncio.create_task(reporter())
    await stop.wait()
    rep.cancel()
    server.close()
    await server.wait_closed()
    log.info("stopped. stats: %s", stats)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

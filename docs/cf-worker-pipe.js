// WSBridge pipe-воркер для Cloudflare Workers.
//
// ИСТОЧНИК: официальный код Flowseal/tg-ws-proxy, docs/RU/CfWorker.md
// https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/docs/RU/CfWorker.md
// ВЗЯТ БЕЗ ИЗМЕНЕНИЙ по логике: это ровно тот контракт, под который
// написан WSBridge iOS (WSClient.connectPipe: wss://<домен>/apiws?dst=<IP>).
//
// Как задеплоить (уникальный воркер, НЕ поверх DoH-воркера):
//   1. dash.cloudflare.com -> Compute -> Workers & Pages -> Create application
//      -> Start with Hello World! -> Deploy (новое имя, например wsbridge-pipe).
//   2. Edit code -> стереть всё слева -> вставить ЭТОТ файл целиком -> Deploy.
//   3. Домен вида random-words.username.workers.dev вписать в WSBridge:
//      Меню -> CF Worker (одно поле; несколько — через запятую).
//   4. Перед этим открыть домен воркера в Safari НА ТЕЛЕФОНЕ: должен
//      открыться (проверка, что *.workers.dev доступен из вашей сети).
//
// Проверка после деплоя: браузером на https://<домен> -> должно быть
// "Expected websocket" (426). Значит воркер жив и ждёт WS-апгрейда.

import { connect } from "cloudflare:sockets";

function toBytes(data) {
	if (data instanceof ArrayBuffer) {
		return new Uint8Array(data);
	}
	if (typeof data === "string") {
		return new TextEncoder().encode(data);
	}
	if (data && typeof data.arrayBuffer === "function") {
		return data.arrayBuffer().then((ab) => new Uint8Array(ab));
	}
	return new Uint8Array();
}

export default {
	async fetch(request) {
		if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
			return new Response("Expected websocket", { status: 426 });
		}

		const url = new URL(request.url);
		if (url.pathname !== "/apiws") {
			return new Response("Not found", { status: 404 });
		}

		const dst = url.searchParams.get("dst");
		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];
		server.accept();

		const socket = connect({ hostname: dst, port: 443 });
		const tcpReader = socket.readable.getReader();
		const tcpWriter = socket.writable.getWriter();

		server.addEventListener("message", async (event) => {
			try {
				await tcpWriter.write(await toBytes(event.data));
			} catch {
				try {
					server.close(1011, "tcp write failed");
				} catch {}
			}
		});

		server.addEventListener("close", async () => {
			try {
				await tcpWriter.close();
			} catch {}
			try {
				socket.close();
			} catch {}
		});

		(async () => {
			try {
				while (true) {
					const { value, done } = await tcpReader.read();
					if (done) {
						break;
					}
					if (value) {
						server.send(value);
					}
				}
			} catch {
			} finally {
				try {
					server.close();
				} catch {}
				try {
					tcpReader.releaseLock();
				} catch {}
				try {
					socket.close();
				} catch {}
			}
		})();

		return new Response(null, { status: 101, webSocket: client });
	},
};

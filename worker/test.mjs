// Локальный self-test воркера без Cloudflare / wrangler / сети.
// Запуск: node test.mjs   (из папки worker/)
// Проверяет критерии этапа 1 из docs/DoH-Routing.ru.md.

import { default as worker } from "./src/index.js";
import assert from "node:assert/strict";

const ENV = {
  MODE: "simple",
  REQUIRE_ID: "true",
  TRUSTED_IDS: "ID-OK-1,ID-OK-2",
  FAKE_IP: "198.18.0.3",
  LISTS: "{}",
};
const CTX = { waitUntil() {} };

// ---- Сборка DNS-запроса (wire) ----
function dnsQuery(name, qtype = 1) {
  const labels = name.split(".").map((l) => [l.length, ...[...l].map((c) => c.charCodeAt(0))]);
  const qname = labels.flat();
  const out = new Uint8Array(12 + qname.length + 1 + 4);
  out[0] = 0x12; out[1] = 0x34;              // ID
  out[2] = 0x01; out[3] = 0x00;              // RD=1
  out[5] = 0x01;                             // QDCOUNT=1
  let p = 12;
  for (const b of qname) out[p++] = b;
  out[p++] = 0;                              // корень
  out[p++] = 0; out[p++] = qtype;
  out[p++] = 0; out[p++] = 1;                // IN
  return out;
}

function parseAnswer(buf) {
  const b = new Uint8Array(buf);
  assert.equal(b.length >= 12, true, "короткий ответ");
  const id = (b[0] << 8) | b[1];
  const qr = (b[2] & 0x80) !== 0;
  const rcode = b[3] & 0x0f;
  const ancount = (b[6] << 8) | b[7];
  let ip = null;
  if (ancount > 0) {
    // ищем указатель 0xc00c и A-запись
    for (let i = 12; i + 16 <= b.length; i++) {
      if (b[i] === 0xc0 && b[i + 1] === 0x0c && b[i + 2] === 0 && b[i + 3] === 1) {
        ip = [b[i + 12], b[i + 13], b[i + 14], b[i + 15]].join(".");
        break;
      }
    }
  }
  return { id, qr, rcode, ancount, ip };
}

function req(path, body, method = "POST") {
  const init = { method, headers: {} };
  if (method === "POST") {
    init.body = body;
    init.headers["Content-Type"] = "application/dns-message";
  }
  return new Request("https://example.workers.dev" + path, init);
}

async function call(path, body, env = ENV, method = "POST") {
  return worker.fetch(req(path, body, method), env, CTX);
}

let passed = 0;
function ok(label) { passed++; console.log("  ✓ " + label); }

// ---------- 1. Простой режим: валидный ID → FakeIP ----------
{
  const q = dnsQuery("gemini.google.com");
  const r = await call("/dns-query/ID-OK-1", q);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("Content-Type"), "application/dns-message");
  const a = parseAnswer(await r.arrayBuffer());
  assert.equal(a.qr, true);
  assert.equal(a.rcode, 0);
  assert.equal(a.ancount, 1);
  assert.equal(a.ip, "198.18.0.3");
  assert.equal(a.id, 0x1234, "ID запроса сохранён");
  ok("POST /dns-query/<валидный ID> → A 198.18.0.3, rcode=NOERROR, id сохранён");
}

// ---------- 2. Любой домен получает FakeIP (воркер не фильтрует) ----------
{
  const q = dnsQuery("example.com");
  const r = await call("/dns-query/ID-OK-1", q);
  const a = parseAnswer(await r.arrayBuffer());
  assert.equal(a.ip, "198.18.0.3");
  ok("простой режим отвечает FakeIP на ЛЮБОЙ домен (фильтр только в matchDomains на iOS)");
}

// ---------- 2b. AAAA / HTTPS RR — пустой NOERROR, БЕЗ A-записи ----------
{
  for (const qtype of [28, 64, 65]) {
    const q = dnsQuery("gemini.google.com", qtype);
    const r = await call("/dns-query/ID-OK-1", q);
    const a = parseAnswer(await r.arrayBuffer());
    assert.equal(a.rcode, 0, "qtype " + qtype + " → NOERROR");
    assert.equal(a.ancount, 0, "qtype " + qtype + " → без A-записи");
    assert.equal(a.ip, null);
  }
  ok("AAAA(28)/SVCB(64)/HTTPS(65) → пустой NOERROR, A-запись не подсовываем");
}

// ---------- 2c. /recent накапливает запросы ----------
{
  const before = JSON.parse(await (await call("/recent", new Uint8Array(0), ENV, "GET")).text());
  assert.ok(Array.isArray(before.items));
  assert.ok(before.items.some((x) => x.qname === "gemini.google.com"));
  ok("GET /recent показывает разобранные qname/path (диагностика этапа 2)");
}

// ---------- 3. Левый ID → REFUSED, HTTP 200 ----------
{
  const q = dnsQuery("gemini.google.com");
  const r = await call("/dns-query/ID-BAD", q);
  assert.equal(r.status, 200, "REFUSED всё равно HTTP 200 по RFC 8484");
  const a = parseAnswer(await r.arrayBuffer());
  assert.equal(a.rcode, 5);
  assert.equal(a.ancount, 0);
  ok("левый ID → DNS REFUSED (HTTP 200, без A-записи)");
}

// ---------- 4. REQUIRE_ID=false → отвечаем всем ----------
{
  const q = dnsQuery("gemini.google.com");
  const r = await call("/dns-query/ID-BAD", q, { ...ENV, REQUIRE_ID: "false" });
  const a = parseAnswer(await r.arrayBuffer());
  assert.equal(a.ip, "198.18.0.3");
  ok("REQUIRE_ID=false отключает защиту: FakeIP даже без доверенного ID");
}

// ---------- 5. GET ?dns=base64url ----------
{
  const q = dnsQuery("gemini.google.com");
  const b64 = Buffer.from(q).toString("base64url");
  const r = await call("/dns-query/ID-OK-1?dns=" + b64, null, ENV, "GET");
  assert.equal(r.status, 200);
  const a = parseAnswer(await r.arrayBuffer());
  assert.equal(a.ip, "198.18.0.3");
  ok("GET ?dns=<base64url> работает (RFC 8484 §4.1)");
}

// ---------- 6. Битый wire → FORMERR ----------
{
  const r = await call("/dns-query/ID-OK-1", new Uint8Array([1, 2, 3]));
  const a = parseAnswer(await r.arrayBuffer());
  assert.equal(a.rcode, 1);
  ok("битый DNS-wire → FORMERR");
}

// ---------- 7. /diagnose JSON ----------
{
  const r = await call("/diagnose", new Uint8Array(0), ENV, "GET");
  assert.equal(r.status, 200);
  const j = JSON.parse(await r.text());
  assert.equal(j.parsed.mode, "simple");
  assert.equal(j.parsed.requireId, true);
  assert.equal(j.config.fakeIp, "198.18.0.3");
  assert.equal(j.errors.length, 0);
  ok("GET /diagnose → JSON с mode/requireId/fakeIp, без ошибок");
}

// ---------- 8. /diagnose с левым ID ----------
{
  const r = await call("/dns-query/ID-BAD/diagnose", new Uint8Array(0), ENV, "GET");
  const j = JSON.parse(await r.text());
  assert.equal(j.parsed.hwidTrusted, false);
  assert.ok(j.errors.some((e) => e.code === "HWID_NOT_TRUSTED"));
  ok("/diagnose с левым ID → HWID_NOT_TRUSTED");
}

// ---------- 9. ID_CHECK_DISABLED в /diagnose ----------
{
  const r = await call("/diagnose", new Uint8Array(0), { ...ENV, REQUIRE_ID: "false" }, "GET");
  const j = JSON.parse(await r.text());
  assert.ok(j.errors.some((e) => e.code === "ID_CHECK_DISABLED"));
  ok("REQUIRE_ID=false → /diagnose показывает ID_CHECK_DISABLED");
}

// ---------- 10. /diagnose с DNS-телом парсит QNAME ----------
{
  const q = dnsQuery("gemini.google.com");
  const r = await call("/diagnose", q);
  const j = JSON.parse(await r.text());
  assert.equal(j.parsed.qname, "gemini.google.com");
  assert.equal(j.parsed.qtype, 1);
  assert.equal(j.parsed.wouldAnswer, "198.18.0.3");
  ok("/diagnose с POST-телом распознаёт qname/qtype/wouldAnswer");
}

// ---------- 11. X-WSBridge-Debug в системном ответе ----------
{
  const q = dnsQuery("gemini.google.com");
  const r = await call("/dns-query/ID-OK-1", q);
  const dbg = r.headers.get("X-WSBridge-Debug");
  assert.ok(dbg);
  const j = JSON.parse(Buffer.from(dbg, "base64").toString("utf8"));
  assert.equal(j.parsed.qname, "gemini.google.com");
  ok("системный ответ несёт X-WSBridge-Debug с разобранным qname");
}

console.log(`\n${passed} проверок пройдено.`);

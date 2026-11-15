// WSBridge DoH worker — MODE="simple" (основной) / MODE="lists" (расширение)
// Документация: worker/README.md · Концепция: docs/DoH-Routing.ru.md (ветка main)
//
// Простой режим: ЛЮБОЙ валидный DNS-запрос → A = FAKE_IP.
// Фильтрация по доменам живёт на iOS в NEDNSOverHTTPSSettings.matchDomains,
// поэтому воркер про списки не знает и никуда не форвардит.
//
// RFC 8484: POST (бинарный DNS-wire в теле) и GET (?dns=<base64url>),
// ответ ВСЕГДА 200 + application/dns-message, ошибки — DNS rcode.

const DEFAULTS = {
  MODE: "simple",
  REQUIRE_ID: "true",
  TRUSTED_IDS: "",
  FAKE_IP: "198.18.1.1",
  UPSTREAM_DOH: "",
  DEFAULT_SETS: "",
  DENY_SETS: "telegram",
  CACHE_TTL: "21600",
  LISTS: "{}",
};

function cfg(env, key) {
  const v = env && env[key] !== undefined ? env[key] : DEFAULTS[key];
  return String(v);
}

// ---------- DNS wire (минимальный парсер/сборщик, без зависимостей) ----------

function parseQName(buf) {
  // buf: Uint8Array, начинается с 12-байтового DNS header
  if (buf.length < 17) return null;
  const labels = [];
  let i = 12;
  while (i < buf.length) {
    const len = buf[i];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) return null; // сжатие в вопросе не бывает
    if (len > 63 || i + 1 + len > buf.length) return null;
    let s = "";
    for (let j = 0; j < len; j++) s += String.fromCharCode(buf[i + 1 + j]);
    labels.push(s);
    i += 1 + len;
  }
  if (!labels.length) return null;
  const qtype = (buf[i + 1] << 8) | buf[i + 2];
  const qclass = (buf[i + 3] << 8) | buf[i + 4];
  return { name: labels.join(".").toLowerCase(), qtype, qclass, end: i + 5, id: (buf[0] << 8) | buf[1] };
}

function buildReply(query, q, rcode, fakeIP) {
  // Ответ = вопрос как есть (до q.end) + одна A-запись.
  // q.end — позиция сразу после QTYPE/QCLASS; хвост запроса (EDNS OPT и пр.)
  // не копируем, чтобы не тащить чужие дополнительные записи.
  const questionLen = q ? q.end : 12;
  const withAnswer = rcode === 0 && !!fakeIP;
  const out = new Uint8Array(questionLen + (withAnswer ? 16 : 0));
  out.set(query.subarray(0, questionLen), 0);
  out[2] = 0x80 | (query[2] & 0x01); // QR=1, RD из запроса
  out[3] = rcode & 0x0f;
  out[6] = 0; out[7] = withAnswer ? 1 : 0; // ANCOUNT
  out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;
  if (withAnswer) {
    let p = questionLen;
    out[p++] = 0xc0; out[p++] = 0x0c;          // NAME = ptr на вопрос
    out[p++] = 0x00; out[p++] = 0x01;          // TYPE A
    out[p++] = 0x00; out[p++] = 0x01;          // CLASS IN
    out[p++] = 0x00; out[p++] = 0x00;
    out[p++] = 0x00; out[p++] = 0x3c;          // TTL 60
    out[p++] = 0x00; out[p++] = 0x04;          // RDLENGTH 4
    for (const oct of fakeIP.split(".")) out[p++] = Number(oct) & 0xff;
  }
  return out;
}

function dnsResponse(body, extraHeaders = {}) {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "application/dns-message",
      "Cache-Control": "max-age=60",
      "Access-Control-Allow-Origin": "*",
      ...extraHeaders,
    },
  });
}

function refused(query, q) {
  return dnsResponse(buildReply(query, q, 5, null));
}

function formerr() {
  const empty = new Uint8Array(12);
  empty[2] = 0x80; empty[3] = 1; // QR=1, FORMERR
  return dnsResponse(empty);
}

function fakeAnswer(query, q, ip) {
  return dnsResponse(buildReply(query, q, 0, ip));
}

// ---------- GET: ?dns=<base64url> ----------

function fromBase64Url(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- Основной обработчик ----------

async function handleDoH(request, env, ctx) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);
  // ["dns-query", "<HWID>"] | ["dns-query", "<HWID>", "id1+id2"]
  const hwid = decodeURIComponent(parts[1] || "");
  const setsSegment = parts[2] || "";

  const mode = cfg(env, "MODE");
  const requireId = cfg(env, "REQUIRE_ID").toLowerCase() === "true";
  const trusted = cfg(env, "TRUSTED_IDS").split(",").map((s) => s.trim()).filter(Boolean);
  const fakeIP = cfg(env, "FAKE_IP");

  const errors = [];
  if (!requireId) {
    errors.push({ code: "ID_CHECK_DISABLED", message: "Защита по ID отключена в wrangler.toml (REQUIRE_ID=false)" });
  }

  // Тело запроса: POST — бинарное, GET — base64url в ?dns=
  let wire;
  if (request.method === "POST") {
    const buf = await request.arrayBuffer();
    wire = new Uint8Array(buf);
  } else if (request.method === "GET") {
    const dns = url.searchParams.get("dns");
    if (!dns) return formerr();
    try { wire = fromBase64Url(dns); } catch { return formerr(); }
  } else {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const q = parseQName(wire);
  if (!q) return formerr();

  const hwidTrusted = requireId ? trusted.includes(hwid) : true;
  if (!hwidTrusted) {
    errors.push({ code: "HWID_NOT_TRUSTED", message: "Добавь этот ID устройства в TRUSTED_IDS" });
    return dnsResponse(buildReply(wire, q, 5, null), debugHeader(mode, requireId, hwid, q, null, setsSegment, errors));
  }

  // ---- Простой режим: отвечаем FakeIP на ЛЮБОЙ дошедший запрос ----
  if (mode === "simple") {
    return dnsResponse(
      buildReply(wire, q, 0, fakeIP),
      debugHeader(mode, requireId, hwid, q, fakeIP, setsSegment, errors)
    );
  }

  // ---- MODE="lists": расширение / резерв Варианта А ----
  return await handleLists(wire, q, env, ctx, hwid, setsSegment, errors, fakeIP, requireId);
}

// ---------- Режим lists (НЕ основной, код рядом, выключен MODE) ----------

async function handleLists(wire, q, env, ctx, hwid, setsSegment, errors, fakeIP, requireId) {
  const upstream = cfg(env, "UPSTREAM_DOH");
  let LISTS = {};
  try { LISTS = JSON.parse(cfg(env, "LISTS")); } catch { /* игнорируем битый конфиг */ }
  const deny = cfg(env, "DENY_SETS").split(",").map((s) => s.trim()).filter(Boolean);
  const requested = (setsSegment || cfg(env, "DEFAULT_SETS"))
    .split("+").map((s) => s.trim()).filter(Boolean);
  const active = requested.filter((id) => id in LISTS && !deny.includes(id));
  const ignored = requested.filter((id) => !(id in LISTS) || deny.includes(id));
  for (const id of ignored) {
    errors.push({ code: "UNKNOWN_LIST", message: `Список '${id}' отсутствует в LISTS или запрещён — проигнорирован` });
  }

  let domainHit = false;
  for (const id of active) {
    const text = await fetchList(LISTS[id], env, ctx);
    if (text && textSet(text).has(q.name)) { domainHit = true; break; }
  }

  if (domainHit) {
    return dnsResponse(buildReply(wire, q, 0, fakeIP),
      debugHeader("lists", requireId, hwid, q, fakeIP, setsSegment, errors));
  }

  if (!upstream) {
    errors.push({ code: "UPSTREAM_UNAVAILABLE", message: "UPSTREAM_DOH не задан" });
    return dnsResponse(buildReply(wire, q, 2, null),
      debugHeader("lists", requireId, hwid, q, null, setsSegment, errors));
  }
  try {
    const up = await fetch(upstream, {
      method: "POST",
      headers: { "Content-Type": "application/dns-message", "Accept": "application/dns-message" },
      body: wire,
    });
    if (!up.ok) throw new Error("upstream " + up.status);
    const answer = new Uint8Array(await up.arrayBuffer());
    const headers = new Headers(up.headers);
    headers.set("Access-Control-Allow-Origin", "*");
    const dbg = debugHeader("lists", requireId, hwid, q, null, setsSegment, errors);
    for (const [k, v] of Object.entries(dbg)) headers.set(k, v);
    return new Response(answer, { status: 200, headers });
  } catch (e) {
    errors.push({ code: "UPSTREAM_UNAVAILABLE", message: String(e) });
    return dnsResponse(buildReply(wire, q, 2, null),
      debugHeader("lists", requireId, hwid, q, null, setsSegment, errors));
  }
}

function textSet(text) {
  const set = new Set();
  for (let line of text.split("\n")) {
    line = line.trim().toLowerCase();
    if (line && !line.startsWith("#")) set.add(line);
  }
  return set;
}

async function fetchList(listURL, env, ctx) {
  if (!listURL) return null;
  const cache = caches.default;
  const key = new Request(listURL);
  const cached = await cache.match(key);
  if (cached) return await cached.text();
  try {
    const ttl = Number(cfg(env, "CACHE_TTL")) || 21600;
    const res = await fetch(listURL, { cf: { cacheTtl: ttl, cacheEverything: true } });
    if (!res.ok) return null;
    const text = await res.text();
    ctx.waitUntil(cache.put(key, new Response(text, { headers: { "Cache-Control": `max-age=${ttl}` } })));
    return text;
  } catch { return null; }
}

// ---------- /diagnose — структурированный JSON для кнопки «Тест воркера» ----------

function debugHeader(mode, requireId, hwid, q, answer, setsSegment, errors) {
  const payload = {
    ok: errors.length === 0,
    version: "1",
    parsed: {
      hwid, hwidTrusted: true, mode, requireId,
      listsRequested: setsSegment ? setsSegment.split("+").filter(Boolean) : [],
      listsActive: [], listsIgnored: [],
      path: q ? `/dns-query/${hwid}${setsSegment ? "/" + setsSegment : ""}` : "",
      method: "POST", contentType: "application/dns-message",
      qname: q ? q.name : null, qtype: q ? q.qtype : null,
      wouldAnswer: answer,
    },
    config: {
      mode, requireId, fakeIp: answer, upstream: null,
      listsConfigured: 0, listsLoaded: 0, cache: "n/a",
    },
    errors,
  };
  return { "X-WSBridge-Debug": btoa(unescape(encodeURIComponent(JSON.stringify(payload)))) };
}

async function diagnose(request, env) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);
  const hwid = decodeURIComponent(parts[1] || "");
  const setsSegment = parts[2] || "";

  const mode = cfg(env, "MODE");
  const requireId = cfg(env, "REQUIRE_ID").toLowerCase() === "true";
  const trusted = cfg(env, "TRUSTED_IDS").split(",").map((s) => s.trim()).filter(Boolean);
  const fakeIP = cfg(env, "FAKE_IP");
  const errors = [];

  if (!requireId) errors.push({ code: "ID_CHECK_DISABLED", message: "Защита по ID отключена (REQUIRE_ID=false)" });
  // Корневой /diagnose — проверка «воркер жив» без ID.
  // Путь /dns-query/<ID>/diagnose — проверка конкретного ID.
  const isRootDiagnose = url.pathname === "/diagnose";
  const hwidTrusted = isRootDiagnose ? true : (requireId ? trusted.includes(hwid) : true);
  if (!isRootDiagnose && !hwidTrusted) {
    errors.push({ code: "HWID_NOT_TRUSTED", message: "Добавь этот ID устройства в TRUSTED_IDS" });
  }

  let qname = null, qtype = null, method = request.method, contentType = request.headers.get("content-type");
  if (request.method === "POST") {
    try {
      const wire = new Uint8Array(await request.arrayBuffer());
      const q = parseQName(wire);
      if (q) { qname = q.name; qtype = q.qtype; }
    } catch { /* /diagnose без тела — это нормально */ }
  }

  let LISTS = {};
  try { LISTS = JSON.parse(cfg(env, "LISTS")); } catch { /* ignore */ }
  const payload = {
    ok: errors.length === 0,
    version: "1",
    parsed: {
      hwid, hwidTrusted, mode, requireId,
      listsRequested: setsSegment ? setsSegment.split("+").filter(Boolean) : [],
      listsActive: mode === "lists" ? Object.keys(LISTS) : [],
      listsIgnored: [],
      path: url.pathname,
      method, contentType, qname, qtype,
      wouldAnswer: hwidTrusted ? fakeIP : null,
    },
    config: {
      mode, requireId, trustedIds: trusted.length, fakeIp: fakeIP,
      upstream: mode === "lists" ? cfg(env, "UPSTREAM_DOH") || null : null,
      listsConfigured: Object.keys(LISTS).length,
      listsLoaded: 0,
      cache: "n/a",
    },
    errors,
  };
  return new Response(JSON.stringify(payload, null, 2), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // /diagnose ловим ДО /dns-query/..., иначе /dns-query/<ID>/diagnose
    // уедет в DNS-обработчик и попытается разобрать JSON как DNS-wire.
    if (url.pathname === "/diagnose" || url.pathname.endsWith("/diagnose")) {
      return diagnose(request, env);
    }
    if (url.pathname.startsWith("/dns-query")) return handleDoH(request, env, ctx);
    return new Response("WSBridge DoH worker. См. /diagnose и README.md", { status: 200 });
  },
};

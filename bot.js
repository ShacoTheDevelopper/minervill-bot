const fs = require("fs");
const crypto = require("crypto");
const https = require("https");
const nacl = require("tweetnacl");
const bs58 = require("bs58");

const BASE_URL = "https://minervill.fun";
const RENEW_MS = 20_000;
const HEARTBEAT_MS = 2_500;
const WORK_ALL_MS = 60_000;
const STATUS_MS = 300_000;

let cookies = [];
let sessionId = null;
let accountId = null;
let running = true;
let lastRenew = 0;
let lastWorkAll = 0;
let lastStatus = 0;
let startedAt = null;
let startTokens = null;
let characters = new Map();

function log(msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}] ${msg}`);
}

function loadConfig() {
  if (process.env.PRIVATE_KEY) {
    return {
      private_key: process.env.PRIVATE_KEY.trim(),
      strategy: process.env.STRATEGY || "max",
    };
  }
  try {
    return JSON.parse(fs.readFileSync("config.json", "utf-8"));
  } catch {
    console.error("No PRIVATE_KEY env var and no config.json found.");
    console.error("Set PRIVATE_KEY in Railway Variables tab.");
    process.exit(1);
  }
}

function uuid() { return crypto.randomUUID(); }

function getKeypair(pk) {
  return nacl.sign.keyPair.fromSecretKey(bs58.default.decode(pk));
}

function getAddress(kp) { return bs58.default.encode(kp.publicKey); }

// ── HTTP ──

function parseCookies(h) {
  const raw = h["set-cookie"];
  if (!raw) return [];
  return (Array.isArray(raw) ? raw : [raw]).map(c => c.split(";")[0].trim()).filter(Boolean);
}

function httpReq(method, path, body = null, extra = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const headers = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      Accept: "*/*", Origin: BASE_URL, Referer: `${BASE_URL}/play/`,
      ...extra,
    };
    if (cookies.length) headers["Cookie"] = cookies.join("; ");
    let data = null;
    if (body !== null) {
      data = JSON.stringify(body);
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(data);
    }
    const req = https.request(
      { hostname: url.hostname, port: 443, path: url.pathname, method, headers },
      res => {
        const chunks = [];
        res.on("data", d => chunks.push(d));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString();
          const nc = parseCookies(res.headers);
          if (nc.length) {
            const map = new Map();
            for (const c of cookies) map.set(c.split("=", 1)[0], c);
            for (const c of nc) map.set(c.split("=", 1)[0], c);
            cookies = [...map.values()];
          }
          let json = null;
          try { json = JSON.parse(raw); } catch {}
          resolve({ status: res.statusCode, json, raw });
        });
      }
    );
    req.setTimeout(15_000, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

const gh = () => accountId ? { "X-Game-Account": accountId } : {};
const apiGet = (p, g) => httpReq("GET", p, null, g ? gh() : {});
const apiPost = (p, b = {}, g) => httpReq("POST", p, b, g ? gh() : {});

// ── Auth ──

async function authenticate(config) {
  const kp = getKeypair(config.private_key);
  const addr = getAddress(kp);
  log(`Auth ${addr.slice(0, 4)}...${addr.slice(-4)}`);

  const ch = await apiPost("/v1/auth/challenge", { address: addr });
  if (ch.status !== 200) throw new Error(`Challenge: ${ch.status}`);

  const msg = new TextEncoder().encode(ch.json.message);
  const sig = nacl.sign.detached(msg, kp.secretKey);

  const vr = await apiPost("/v1/auth/verify", {
    challengeId: ch.json.challengeId,
    signature: Buffer.from(sig).toString("base64"),
    signedMessage: Buffer.from(msg).toString("base64"),
  });
  if (vr.status !== 200) throw new Error(`Verify: ${vr.status}`);

  const me = await apiGet("/v1/me");
  if (me.status !== 200) throw new Error(`/me: ${me.status}`);

  accountId = me.json.user?.id || me.json.id;
  log(`Logged in: ${addr.slice(0, 4)}...${addr.slice(-4)} (${me.json.wallet?.cluster})`);
  return me.json;
}

async function ensureAuth(config) {
  try {
    const me = await apiGet("/v1/me");
    if (me.status === 200 && me.json) {
      accountId = me.json.user?.id || me.json.id;
      return me.json;
    }
  } catch {}
  return authenticate(config);
}

// ── Mining API ──

const getSession = async () => { const r = await apiGet("/v1/game/mining/session", true); if (r.status !== 200) throw new Error(`session: ${r.status}`); return r.json; };
const getState = async () => { const r = await apiGet("/v1/game/state", true); if (r.status !== 200) throw new Error(`state: ${r.status}`); return r.json; };
const doStart = async (cfg) => { const r = await apiPost("/v1/game/mining/start", { requestId: uuid(), policy: cfg.strategy || "max" }, true); return r.status === 200 ? r.json : null; };
const doRenew = async (id) => { const r = await apiPost("/v1/game/mining/renew", { requestId: uuid(), sessionId: id }, true); return r.status === 200 ? r.json : null; };
const doStop = async (id) => { const r = await apiPost("/v1/game/mining/stop", { requestId: uuid(), sessionId: id }, true); return r.json; };
const doWorkAll = async (id) => { const r = await apiPost("/v1/game/mining/work_all", { requestId: uuid(), sessionId: id }, true); return r.status === 200 ? r.json : null; };

// ── Formatting ──

function tokens(units) {
  const n = parseInt(units, 10);
  if (isNaN(n)) return "0.00";
  return (n / 1_000_000).toFixed(2);
}

function pct(bps) {
  return `${(parseFloat(bps) / 100).toFixed(1)}%`;
}

function bar(bps) {
  const p = parseFloat(bps) / 100;
  const filled = Math.round(p / 5);
  return "█".repeat(filled) + "░".repeat(20 - filled);
}

function elapsed(ms) {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h${m.toString().padStart(2, "0")}m`;
  return `${m}m`;
}

// ── Display ──

function printMiners(session) {
  const workers = session.workers || [];
  if (!workers.length) return;

  console.log("");
  console.log("  Name         Rarity     Stamina");
  console.log("  ─────────────────────────────────────────────────");
  for (const w of workers) {
    const char = characters.get(w.character_id);
    const name = (char?.name || w.character_id.slice(0, 8)).padEnd(12);
    const rarity = (char?.rarity || "?").padEnd(10);
    const stam = pct(w.stamina_bps).padStart(6);
    const b = bar(w.stamina_bps);
    console.log(`  ${name} ${rarity} ${stam} ${b}`);
  }
  console.log("");
}

function calcEarnings(currentTokens) {
  if (startTokens === null || startedAt === null) return null;
  const mined = parseInt(currentTokens, 10) - startTokens;
  const elapsedMs = Date.now() - startedAt;
  if (elapsedMs < 60_000 || mined <= 0) return null;

  const hours = elapsedMs / 3_600_000;
  const perHour = mined / hours;
  const perDay = perHour * 24;

  return {
    mined: (mined / 1_000_000).toFixed(2),
    perHour: (perHour / 1_000_000).toFixed(2),
    perDay: (perDay / 1_000_000).toFixed(2),
    elapsed: elapsed(elapsedMs),
  };
}

function printStatus(session, state) {
  const today = tokens(state?.todayMining?.creditedUnits || "0");
  const balance = tokens(state?.balance?.units || "0");
  const available = tokens(session?.tokenRewards?.availableUnits || "0");

  console.log("");
  console.log("  ┌──────────────────────────────────────┐");
  console.log(`  │  Today: ${today.padStart(10)} VILL            │`);
  console.log(`  │  Balance: ${balance.padStart(8)} VILL            │`);
  console.log(`  │  Available: ${available.padStart(6)} VILL            │`);

  if (state?.todayMining?.creditedUnits) {
    const earnings = calcEarnings(state.todayMining.creditedUnits);
    if (earnings) {
      console.log("  ├──────────────────────────────────────┤");
      console.log(`  │  Bot uptime: ${earnings.elapsed.padStart(8)}                │`);
      console.log(`  │  Mined (bot): ${earnings.mined.padStart(7)} VILL            │`);
      console.log(`  │  Rate: ${earnings.perHour.padStart(10)} VILL/hr          │`);
      console.log(`  │  Est. daily: ${earnings.perDay.padStart(8)} VILL            │`);
    }
  }

  console.log("  └──────────────────────────────────────┘");

  printMiners(session);
}

// ── Main ──

async function mainLoop(config) {
  let errors = 0;

  await ensureAuth(config);

  // Load character names
  try {
    const state = await getState();
    for (const c of state.characters || []) characters.set(c.id, c);
    log(`Loaded ${characters.size} characters`);
  } catch {}

  // Handle existing session
  let session;
  try { session = await getSession(); } catch { session = null; }

  if (session?.lease?.status === "active") {
    log(`Stopping old session...`);
    try { await doStop(session.lease.id); } catch {}
    log(`Waiting for lease to expire (~90s)...`);
    let expired = false;
    for (let i = 0; i < 24; i++) {
      await sleep(5_000);
      try {
        const s = await getSession();
        if (s?.lease?.status !== "active") { expired = true; break; }
        if (i % 6 === 5) {
          const ttl = Math.max(0, (new Date(s.lease.expires_at).getTime() - Date.now()) / 1000);
          log(`Still active (${ttl.toFixed(0)}s). Close your browser tab if open!`);
        }
      } catch { expired = true; break; }
    }
    if (!expired) {
      log("Session won't expire. Close the game in your browser first!");
      log("Retrying in 60s...");
      await sleep(60_000);
      return mainLoop(config);
    }
  }

  // Start mining
  const result = await doStart(config);
  if (!result?.lease) {
    log("Start failed. Retrying in 30s...");
    await sleep(30_000);
    return mainLoop(config);
  }

  sessionId = result.lease.id;
  lastRenew = Date.now();
  log(`Mining started (${config.strategy})`);

  // Record starting point for earnings calc
  try {
    const state = await getState();
    startedAt = Date.now();
    startTokens = parseInt(state.todayMining?.creditedUnits || "0", 10);
    lastStatus = Date.now();
    printStatus(result, state);
  } catch {
    printMiners(result);
    lastStatus = Date.now();
  }

  // Main loop
  while (running) {
    try {
      const now = Date.now();

      // Renew lease
      if (now - lastRenew >= RENEW_MS) {
        const renewed = await doRenew(sessionId);
        if (renewed) {
          lastRenew = now;
        } else {
          log("Renew failed, recovering...");
          try {
            session = await getSession();
            if (session?.lease?.status === "active") {
              sessionId = session.lease.id;
              lastRenew = now;
            } else {
              await ensureAuth(config);
              const r = await doStart(config);
              if (r?.lease) { sessionId = r.lease.id; lastRenew = Date.now(); }
              else { await sleep(30_000); continue; }
            }
          } catch {
            await ensureAuth(config);
            const r = await doStart(config);
            if (r?.lease) { sessionId = r.lease.id; lastRenew = Date.now(); }
            else { await sleep(30_000); continue; }
          }
        }
        errors = 0;
      }

      // Send miners to work
      if (now - lastWorkAll >= WORK_ALL_MS) {
        lastWorkAll = now;
        try {
          session = await getSession();
          if (session?.workAllEnabled) await doWorkAll(sessionId);
        } catch {}
      }

      // Status report
      if (now - lastStatus >= STATUS_MS) {
        lastStatus = now;
        try {
          session = await getSession();
          const state = await getState();
          printStatus(session, state);
        } catch (e) {
          log(`Status error: ${e.message}`);
        }
      }

      await sleep(HEARTBEAT_MS);
    } catch (e) {
      errors++;
      const wait = Math.min(30_000 * errors, 300_000);
      log(`Error: ${e.message} (retry ${wait / 1000}s)`);
      if (errors >= 3) try { await ensureAuth(config); } catch {}
      await sleep(wait);
    }
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function shutdown() {
  log("Shutting down...");
  running = false;
  if (sessionId) try { await doStop(sessionId); } catch {}
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

async function main() {
  console.log("\n  ⛏  MinerVill Bot\n");

  const config = loadConfig();
  if (!config.private_key || config.private_key === "YOUR_SOLANA_PRIVATE_KEY_BASE58_HERE") {
    console.error("Set your Solana private key in config.json or PRIVATE_KEY env var.");
    process.exit(1);
  }

  while (true) {
    try {
      await mainLoop(config);
    } catch (e) {
      log(`Fatal: ${e.message}`);
      await sleep(60_000);
    }
  }
}

main();

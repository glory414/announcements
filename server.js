/*
 * ACCESS TERMINAL — relay server v2  (accounts · bans · notifications · announcements · chat)
 * ---------------------------------------------------------------------------------------------
 * What it does
 *   • Accounts live HERE. The public build signs in against this server; the server assigns each
 *     person their display name, so nobody can chat as somebody else.
 *   • The admin (the developer build + ADMIN_KEY) can ban / unban accounts, push notifications to one
 *     person or everyone, post announcements, and add accounts.
 *   • Chat rooms, as before.
 *
 * Environment variables
 *   ADMIN_KEY      secret for the admin (falls back to ANNOUNCE_KEY, which you may already have set).
 *   GIST_ID +      OPTIONAL BUT STRONGLY RECOMMENDED on Render's free tier. Keeps accounts, bans and
 *   GITHUB_TOKEN   announcements in a private GitHub Gist so they survive restarts. Without them the
 *                  state is written to a file on this server's disk, which Render's free tier wipes
 *                  on every restart/redeploy — bans would silently disappear.
 *   STATE_FILE     file used when no Gist is configured (default ./state.json)
 *   SEED_FILE      accounts to create on first start (default ./seed-accounts.json)
 *   PORT           provided by Render.
 *
 * Run:  npm install && ADMIN_KEY="long-random-secret" node server.js
 * Clients connect to  wss://<your-service>.onrender.com/ws
 * Optional: put your PUBLIC html file next to this one named index.html and it is served at "/".
 */
"use strict";
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = Number(process.env.PORT) || 8080;
const ADMIN_KEY = process.env.ADMIN_KEY || process.env.ANNOUNCE_KEY || "";
const STATE_FILE = process.env.STATE_FILE || path.join(__dirname, "state.json");
const SEED_FILE = process.env.SEED_FILE || path.join(__dirname, "seed-accounts.json");
const GIST_ID = process.env.GIST_ID || "";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const GITHUB_API = (process.env.GITHUB_API || "https://api.github.com").replace(/\/$/, "");
const MODE = GIST_ID && GITHUB_TOKEN ? "gist" : "file";
const PBKDF2_ITER = 100000;
const LIMITS = { name: 24, room: 32, chat: 500, announce: 1000, nTitle: 60, nText: 300, username: 32, password: 128, reason: 120 };
const TOKEN_DAYS = 90, MAX_TOKENS = 8, MAX_ANN = 50, MAX_NOTIF = 200, NOTIF_KEEP_DAYS = 7;

/* ---------------------------------------------------------------- helpers */
const sha256 = s => crypto.createHash("sha256").update(String(s)).digest();
const sha256hex = s => sha256(s).toString("hex");
const safeEqual = (a, b) => crypto.timingSafeEqual(sha256(a), sha256(b));
const cleanLine = (s, max) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max);
const cleanText = (s, max) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").trim().slice(0, max);
const norm = u => String(u == null ? "" : u).trim().toLowerCase().replace(/[\u2018\u2019\u02bc]/g, "'");
const sleep = ms => new Promise(r => setTimeout(r, ms));
const pbkdf2 = (pw, saltHex, it) => new Promise((res, rej) =>
  crypto.pbkdf2(pw, Buffer.from(saltHex, "hex"), it, 32, "sha256", (e, k) => (e ? rej(e) : res(k.toString("hex")))));
async function makeCredential(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, it: PBKDF2_ITER, ph: await pbkdf2(password, salt, PBKDF2_ITER) };
}
const DUMMY = { salt: "00".repeat(16), it: PBKDF2_ITER };      // unknown username: do the same work so timing doesn't reveal it
let lastTime = 0;
const nextTime = () => (lastTime = Math.max(Date.now(), lastTime + 1));

/* ---------------------------------------------------------------- persistent state */
let state = { v: 2, accounts: {}, announcements: [], notifications: [] };
let dirty = false, saving = false, saveTimer = null, saveFailDelay = 5000, lastSaveError = "";

const ghHeaders = () => ({ Authorization: "Bearer " + GITHUB_TOKEN, Accept: "application/vnd.github+json",
  "User-Agent": "access-terminal-relay", "X-GitHub-Api-Version": "2022-11-28" });
async function gistLoad() {
  const r = await fetch(`${GITHUB_API}/gists/${GIST_ID}`, { headers: ghHeaders() });
  if (!r.ok) throw new Error("gist load failed: HTTP " + r.status);
  const j = await r.json();
  const f = j.files && j.files["state.json"];
  if (!f) return null;                                            // brand-new gist: nothing saved yet
  let content = f.content;
  if (f.truncated && f.raw_url) content = await (await fetch(f.raw_url, { headers: ghHeaders() })).text();
  return JSON.parse(content);
}
async function gistSave(text) {
  const r = await fetch(`${GITHUB_API}/gists/${GIST_ID}`, { method: "PATCH", headers: { ...ghHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ files: { "state.json": { content: text } } }) });
  if (!r.ok) throw new Error("gist save failed: HTTP " + r.status);
}
async function loadState() {
  let loaded = null;
  if (MODE === "gist") loaded = await gistLoad();
  else { try { loaded = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch (e) { if (e.code !== "ENOENT") throw new Error("state file unreadable: " + e.message); } }
  if (loaded && typeof loaded === "object") state = Object.assign({ v: 2, accounts: {}, announcements: [], notifications: [] }, loaded);
  if (!state.accounts || typeof state.accounts !== "object") state.accounts = {};
  mergeSeed();
}
async function loadWithRetry() {
  // Never start with an empty state when the real one couldn't be read — the next save would overwrite it.
  const retries = Number(process.env.GIST_LOAD_RETRIES ?? 5), base = Number(process.env.GIST_RETRY_MS || 2000);
  for (let i = 0; ; i++) {
    try { await loadState(); return; }
    catch (e) { if (MODE !== "gist" || i >= retries) throw e; console.warn("state load failed (" + e.message + ") — retrying…"); await sleep(base * 2 ** i); }
  }
}
function mergeSeed() {
  let seed = [];
  try { seed = JSON.parse(fs.readFileSync(SEED_FILE, "utf8")); } catch (e) { if (e.code !== "ENOENT") console.warn("seed file unreadable:", e.message); }
  let added = 0;
  for (const s of Array.isArray(seed) ? seed : []) {
    const key = norm(s.username);
    if (!key || state.accounts[key] || !s.salt || !s.ph) continue;   // never overwrite (or resurrect over) what's stored
    state.accounts[key] = { username: String(s.username), name: cleanLine(s.name, LIMITS.name) || String(s.username), salt: s.salt, ph: s.ph, it: s.it || PBKDF2_ITER,
      banned: false, bannedReason: "", bannedAt: 0, createdAt: Date.now(), lastSeen: 0, notifCursor: Date.now(), tokens: [] };
    added++;
  }
  if (added) { console.log(`seeded ${added} account(s)`); scheduleSave(); }
}
function scheduleSave() { dirty = true; if (!saveTimer) saveTimer = setTimeout(runSave, 1500); }
async function runSave() {
  saveTimer = null;
  if (saving || !dirty) return;
  saving = true; dirty = false;
  const text = JSON.stringify(state);
  try {
    if (MODE === "gist") await gistSave(text);
    else { fs.writeFileSync(STATE_FILE + ".tmp", text); fs.renameSync(STATE_FILE + ".tmp", STATE_FILE); }
    saveFailDelay = 5000; lastSaveError = "";
  } catch (e) {
    lastSaveError = e.message; console.warn("save failed:", e.message);
    dirty = true; saveTimer = setTimeout(runSave, saveFailDelay); saveFailDelay = Math.min(60000, saveFailDelay * 2);
  } finally { saving = false; if (dirty && !saveTimer) saveTimer = setTimeout(runSave, 1500); }
}
async function flushNow() { if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; } while (saving) await sleep(50); dirty = true; await runSave(); }

/* ---------------------------------------------------------------- runtime registries */
const online = new Map();          // account key -> Set(ws)
const admins = new Set();
const loginFails = new Map();      // "key" / "r:key" -> timestamps of recent failures
function failCount(k) { const now = Date.now(), l = (loginFails.get(k) || []).filter(t => now - t < 10 * 60000); loginFails.set(k, l); return l.length; }
function noteFail(k) { failCount(k); loginFails.get(k).push(Date.now()); }
function allow(ws, kind, perMinute) {
  const now = Date.now(), w = (ws.hits[kind] = (ws.hits[kind] || []).filter(t => now - t < 60000));
  if (w.length >= perMinute) return false;
  w.push(now); return true;
}
const send = (ws, obj) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); };
const isAdmin = ws => !!ws.auth && ws.auth.kind === "admin";
const isUser = ws => !!ws.auth && ws.auth.kind === "user";
const userSockets = key => online.get(key) || new Set();

function publicAccount(a, key) {
  return { key, username: a.username, name: a.name, banned: !!a.banned, bannedReason: a.bannedReason || "", bannedAt: a.bannedAt || 0,
    online: userSockets(key).size, lastSeen: a.lastSeen || 0, createdAt: a.createdAt || 0 };
}
function adminSnapshot() {
  const accounts = Object.keys(state.accounts).map(k => publicAccount(state.accounts[k], k)).sort((a, b) => a.name.localeCompare(b.name));
  return { type: "admin_state", accounts, onlineUsers: accounts.filter(a => a.online > 0).length, storage: MODE, saveError: lastSaveError };
}
let adminPushTimer = null;
function pushAdminState() {
  if (adminPushTimer) return;
  adminPushTimer = setTimeout(() => { adminPushTimer = null; const snap = adminSnapshot(); for (const ws of admins) send(ws, snap); }, 250);
}
const clientNotif = n => ({ id: n.id, title: n.title, text: n.text, time: n.time, from: n.from || "Admin" });

/* ---------------------------------------------------------------- tokens / auth */
function issueToken(acct) {
  const secret = crypto.randomBytes(32).toString("base64url");
  acct.tokens = (acct.tokens || []).filter(t => t.exp > Date.now());
  acct.tokens.push({ h: sha256hex(secret), exp: Date.now() + TOKEN_DAYS * 864e5 });
  acct.tokens = acct.tokens.slice(-MAX_TOKENS);
  scheduleSave();
  return secret;
}
function attachUser(ws, key, acct) {
  ws.auth = { kind: "user", key };
  if (!online.has(key)) online.set(key, new Set());
  online.get(key).add(ws);
  acct.lastSeen = Date.now(); scheduleSave(); pushAdminState();
}
function bannedText(acct) { return acct.bannedReason ? "Your account has been banned: " + acct.bannedReason : "Your account has been banned."; }
function deliverPending(ws, acct) {
  const key = ws.auth.key, now = Date.now();
  const items = state.notifications.filter(n => n.time > (acct.notifCursor || 0) && now - n.time < NOTIF_KEEP_DAYS * 864e5 && (n.to === "all" || n.to === key));
  if (items.length) send(ws, { type: "notification_batch", items: items.map(clientNotif) });
  const latest = state.notifications.length ? state.notifications[state.notifications.length - 1].time : 0;
  if (latest > (acct.notifCursor || 0)) { acct.notifCursor = latest; scheduleSave(); }
}
async function handleAuth(ws, msg) {
  const key = norm(cleanLine(msg.username, LIMITS.username));
  const pw = typeof msg.password === "string" ? msg.password.slice(0, LIMITS.password) : "";
  const fails = failCount(key);
  if (fails) await sleep(Math.min(10000, 700 * fails));           // slows guessing without ever locking a real user out
  const acct = state.accounts[key], ref = acct || DUMMY;
  const got = pw ? await pbkdf2(pw, ref.salt, ref.it) : "";
  if (!acct || !pw || !safeEqual(got, acct.ph)) {
    noteFail(key); ws.authFails = (ws.authFails || 0) + 1;
    send(ws, { type: "auth_error", reason: "bad_credentials", text: "Incorrect username or password." });
    if (ws.authFails >= 5) ws.close(4001, "too many attempts");
    return;
  }
  if (acct.banned) { send(ws, { type: "auth_error", reason: "banned", text: bannedText(acct) }); setTimeout(() => ws.close(4003, "banned"), 200); return; }
  loginFails.delete(key);
  const token = issueToken(acct);
  attachUser(ws, key, acct);
  send(ws, { type: "auth_ok", name: acct.name, username: acct.username, token });
}
async function handleResume(ws, msg) {
  const key = norm(cleanLine(msg.username, LIMITS.username)), token = typeof msg.token === "string" ? msg.token.slice(0, 100) : "";
  const fails = failCount("r:" + key);
  if (fails) await sleep(Math.min(5000, 500 * fails));
  const acct = state.accounts[key], h = sha256hex(token), now = Date.now();
  const valid = !!acct && !!token && (acct.tokens || []).some(t => t.exp > now && safeEqual(t.h, h));
  if (!valid) {
    noteFail("r:" + key); ws.authFails = (ws.authFails || 0) + 1;
    send(ws, { type: "auth_error", reason: "bad_token", text: "Your session expired — please sign in again." });
    if (ws.authFails >= 5) ws.close(4001, "too many attempts");
    return;
  }
  if (acct.banned) { send(ws, { type: "auth_error", reason: "banned", text: bannedText(acct) }); setTimeout(() => ws.close(4003, "banned"), 200); return; }
  attachUser(ws, key, acct);
  send(ws, { type: "auth_ok", name: acct.name, username: acct.username });
}
async function handleAdminAuth(ws, msg) {
  const fails = ws.adminFails || 0;
  if (fails) await sleep(Math.min(5000, 600 * fails));
  if (!ADMIN_KEY || typeof msg.key !== "string" || !safeEqual(msg.key, ADMIN_KEY)) {
    ws.adminFails = fails + 1;
    send(ws, { type: "auth_error", reason: "bad_key", text: ADMIN_KEY ? "Wrong admin key." : "Admin access isn't enabled on this server (set ADMIN_KEY)." });
    if (ws.adminFails >= 5) ws.close(4001, "too many attempts");
    return;
  }
  ws.auth = { kind: "admin" }; admins.add(ws);
  send(ws, { type: "admin_ok" });
  send(ws, adminSnapshot());
}

/* ---------------------------------------------------------------- admin actions */
const result = (ws, action, ok, text) => send(ws, { type: "admin_result", action, ok, text });
function doBan(key, reason) {
  const a = state.accounts[key];
  a.banned = true; a.bannedReason = reason; a.bannedAt = Date.now(); a.tokens = [];
  scheduleSave();
  for (const s of [...userSockets(key)]) { send(s, { type: "banned", text: bannedText(a) }); setTimeout(() => { try { s.close(4003, "banned"); } catch {} }, 250); }
  pushAdminState();
}
function doNotify(to, title, text) {
  const eligible = to === "all" ? Object.keys(state.accounts).filter(k => !state.accounts[k].banned) : [to];
  const rec = { id: Date.now().toString(36) + crypto.randomBytes(3).toString("hex"), to, title, text, time: nextTime(), from: "Admin" };
  state.notifications.push(rec);
  state.notifications = state.notifications.slice(-MAX_NOTIF);
  let delivered = 0;
  for (const k of eligible) {
    const socks = userSockets(k);
    if (!socks.size) continue;
    for (const s of socks) send(s, Object.assign({ type: "notification" }, clientNotif(rec)));
    delivered++; state.accounts[k].notifCursor = rec.time;
  }
  scheduleSave();
  return { delivered, queued: eligible.length - delivered };
}
async function handleAdmin(ws, msg) {
  switch (msg.type) {
    case "admin_state": send(ws, adminSnapshot()); return;
    case "admin_ban": {
      const key = norm(msg.username), a = state.accounts[key];
      if (!a) return result(ws, "ban", false, "No such account.");
      if (a.banned) return result(ws, "ban", false, a.name + " is already banned.");
      doBan(key, cleanLine(msg.reason, LIMITS.reason));
      return result(ws, "ban", true, "Banned " + a.name + ".");
    }
    case "admin_unban": {
      const key = norm(msg.username), a = state.accounts[key];
      if (!a) return result(ws, "unban", false, "No such account.");
      if (!a.banned) return result(ws, "unban", false, a.name + " isn't banned.");
      a.banned = false; a.bannedReason = ""; a.bannedAt = 0; scheduleSave(); pushAdminState();
      return result(ws, "unban", true, "Unbanned " + a.name + ". They can sign in again.");
    }
    case "admin_notify": {
      const to = msg.to === "all" ? "all" : norm(msg.to);
      const text = cleanText(msg.text, LIMITS.nText), title = cleanLine(msg.title, LIMITS.nTitle);
      if (!text) return result(ws, "notify", false, "Write a message first.");
      if (to !== "all") {
        const a = state.accounts[to];
        if (!a) return result(ws, "notify", false, "No such account.");
        if (a.banned) return result(ws, "notify", false, a.name + " is banned.");
      }
      const r = doNotify(to, title, text);
      return result(ws, "notify", true, `Delivered now to ${r.delivered} online account${r.delivered === 1 ? "" : "s"}` +
        (r.queued ? `; ${r.queued} offline will get it when they next connect (within ${NOTIF_KEEP_DAYS} days).` : "."));
    }
    case "admin_create": {
      const username = cleanLine(msg.username, LIMITS.username), key = norm(username);
      const name = cleanLine(msg.name, LIMITS.name) || username, pw = typeof msg.password === "string" ? msg.password : "";
      if (!/^[A-Za-z0-9_.'-]{2,32}$/.test(username)) return result(ws, "create", false, "Username: 2–32 letters, numbers, . _ - '");
      if (pw.length < 6 || pw.length > LIMITS.password) return result(ws, "create", false, "Password must be 6–128 characters.");
      if (state.accounts[key]) return result(ws, "create", false, "That username already exists.");
      const cred = await makeCredential(pw);
      if (state.accounts[key]) return result(ws, "create", false, "That username already exists.");
      state.accounts[key] = Object.assign({ username, name, banned: false, bannedReason: "", bannedAt: 0, createdAt: Date.now(), lastSeen: 0, notifCursor: Date.now(), tokens: [] }, cred);
      scheduleSave(); pushAdminState();
      return result(ws, "create", true, `Created ${name} (${username}).`);
    }
  }
}

/* ---------------------------------------------------------------- message router */
async function handle(ws, msg) {
  if (!msg || typeof msg !== "object" || typeof msg.type !== "string") return;
  if (!ws.auth) {
    if (msg.type === "auth") return handleAuth(ws, msg);
    if (msg.type === "resume") return handleResume(ws, msg);
    if (msg.type === "admin") return handleAdminAuth(ws, msg);
    return send(ws, { type: "auth_error", reason: "auth_required", text: "Sign in first." });
  }
  if (msg.type.startsWith("admin_")) {
    if (!isAdmin(ws)) return send(ws, { type: "auth_error", reason: "forbidden", text: "Admin only." });
    return handleAdmin(ws, msg);
  }
  if (isUser(ws)) {                                               // a ban applies immediately, even to an open connection
    const a = state.accounts[ws.auth.key];
    if (!a || a.banned) { send(ws, { type: "banned", text: a ? bannedText(a) : "Your account no longer exists." }); setTimeout(() => ws.close(4003, "banned"), 200); return; }
  }
  const display = () => isUser(ws) ? state.accounts[ws.auth.key].name : (cleanLine(msg.name, LIMITS.name) || ws.name || "Admin");

  if (msg.type === "join") {
    ws.room = cleanLine(msg.room, LIMITS.room) || "general";
    if (isAdmin(ws)) ws.name = cleanLine(msg.name, LIMITS.name) || "Admin";
    ws.joined = true;
    send(ws, { type: "announcement_history", items: state.announcements });
    if (isUser(ws)) deliverPending(ws, state.accounts[ws.auth.key]);   // queued notifications go to a real chat connection, not the throw-away sign-in one
    return;
  }
  if (!ws.joined) return;
  if (msg.type === "chat") {
    if (!allow(ws, "chat", 40)) return;
    const text = cleanLine(msg.text, LIMITS.chat);
    if (!text) return;
    const out = { type: "chat", text, name: display() };          // the name always comes from the server, never from the client
    for (const c of wss.clients) if (c !== ws && c.auth && c.joined && c.room === ws.room) send(c, out);
    return;
  }
  if (msg.type === "announce") {
    if (!isAdmin(ws)) return send(ws, { type: "announce_error", text: "Only the admin can post announcements." });
    if (!allow(ws, "announce", 20)) return send(ws, { type: "announce_error", text: "Slow down — too many announcements." });
    const text = cleanText(msg.text, LIMITS.announce);
    if (!text) return;
    const item = { id: Date.now().toString(36) + crypto.randomBytes(3).toString("hex"), name: cleanLine(msg.name, LIMITS.name) || ws.name || "Admin", text, time: nextTime() };
    state.announcements.push(item); state.announcements = state.announcements.slice(-MAX_ANN); scheduleSave();
    const out = Object.assign({ type: "announcement" }, item);
    for (const c of wss.clients) if (c.auth) send(c, out);
  }
}

/* ---------------------------------------------------------------- server */
const PAGE = path.join(__dirname, "index.html");
const server = http.createServer((req, res) => {
  const url = String(req.url || "/").split("?")[0];
  if ((url === "/" || url === "/index.html") && fs.existsSync(PAGE)) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
    fs.createReadStream(PAGE).pipe(res);
    return;
  }
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("access-terminal relay v2: ok\n");
});
const wss = new WebSocketServer({ server, path: "/ws", maxPayload: 8 * 1024 });
wss.on("connection", ws => {
  ws.isAlive = true; ws.hits = {}; ws.auth = null; ws.joined = false; ws.room = "general"; ws.q = Promise.resolve();
  ws.on("pong", () => { ws.isAlive = true; });
  ws.on("message", raw => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }
    ws.q = ws.q.then(() => handle(ws, msg)).catch(e => console.warn("handler error:", e && e.message));   // one message at a time per socket
  });
  ws.on("close", () => {
    if (isAdmin(ws)) admins.delete(ws);
    if (isUser(ws)) {
      const set = online.get(ws.auth.key);
      if (set) { set.delete(ws); if (!set.size) { online.delete(ws.auth.key); const a = state.accounts[ws.auth.key]; if (a) { a.lastSeen = Date.now(); scheduleSave(); } } }
      pushAdminState();
    }
  });
});
setInterval(() => {
  for (const ws of wss.clients) { if (!ws.isAlive) { ws.terminate(); continue; } ws.isAlive = false; try { ws.ping(); } catch {} }
}, 30000).unref();

async function shutdown() { try { await flushNow(); } catch {} process.exit(0); }
process.on("SIGTERM", shutdown); process.on("SIGINT", shutdown);

(async () => {
  try { await loadWithRetry(); }
  catch (e) { console.error("FATAL: couldn't load saved state —", e.message); process.exit(1); }
  if (!ADMIN_KEY) console.warn("WARNING: ADMIN_KEY is not set — the admin panel and announcements are disabled.");
  else if (ADMIN_KEY.length < 16) console.warn("WARNING: ADMIN_KEY is short. Use 20+ random characters.");
  if (MODE === "file") console.warn("NOTE: no GIST_ID/GITHUB_TOKEN — state is saved to this server's disk. On Render's free tier that is wiped on restart, so bans and new accounts would be lost.");
  console.log(`relay v2 listening on :${PORT} — ${Object.keys(state.accounts).length} account(s), storage: ${MODE}`);
  server.listen(PORT);
})();

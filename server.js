/*
 * ACCESS TERMINAL — chat + announcements relay
 * -------------------------------------------------------------
 * Speaks the same protocol the terminal already uses
 *   client -> {type:"join",  room, name}
 *   client -> {type:"chat",  room, text, name}        (relayed to everyone else in the room)
 * and adds announcements:
 *   client -> {type:"announce", name, text, key}      (ONLY accepted if key === ANNOUNCE_KEY)
 *   server -> {type:"announcement", id, name, text, time}           (to every connected client)
 *   server -> {type:"announcement_history", items:[...]}            (sent to each client on join)
 *   server -> {type:"announce_error", text}                         (rejected post)
 *
 * This is what makes "public = read-only, developer = can post" real: the check
 * happens HERE, so editing the HTML or using the browser console can't get around it.
 *
 * Run:     npm install && ANNOUNCE_KEY="a-long-random-secret" node server.js
 * Render:  Build command `npm install`, Start command `node server.js`,
 *          and add an environment variable ANNOUNCE_KEY (use 20+ random characters).
 *          Clients connect to  wss://<your-service>.onrender.com/ws
 *
 * Note: announcement history is kept in memory and best-effort saved to a file.
 * On Render's free tier the disk is wiped on every redeploy/restart, so old
 * announcements can disappear (clients also keep their own cached copy).
 */
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = Number(process.env.PORT) || 8080;
const ANNOUNCE_KEY = process.env.ANNOUNCE_KEY || "";
const HISTORY_FILE = process.env.ANNOUNCE_FILE || path.join(__dirname, "announcements.json");
const MAX_HISTORY = 50;
const LIMITS = { name: 24, room: 32, chat: 500, announce: 1000 };

if (!ANNOUNCE_KEY) console.warn("WARNING: ANNOUNCE_KEY is not set — announcements are disabled until you set it.");
else if (ANNOUNCE_KEY.length < 16) console.warn("WARNING: ANNOUNCE_KEY is short. Use 20+ random characters.");

/* ---------- helpers ---------- */
const digest = s => crypto.createHash("sha256").update(String(s)).digest();
const keyOk = k => ANNOUNCE_KEY.length > 0 && typeof k === "string" && crypto.timingSafeEqual(digest(k), digest(ANNOUNCE_KEY));
const cleanLine = (s, max) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max);
const cleanText = (s, max) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").trim().slice(0, max);
const ipOf = req => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

/* ---------- announcement history ---------- */
let history = [];
try { history = JSON.parse(fs.readFileSync(HISTORY_FILE, "utf8")).slice(-MAX_HISTORY); } catch { history = []; }
function saveHistory() { try { fs.writeFileSync(HISTORY_FILE, JSON.stringify(history)); } catch {} }

/* ---------- abuse limits ---------- */
function allow(ws, kind, perMinute) {            // simple per-connection sliding window
  const now = Date.now();
  const w = (ws.hits[kind] = (ws.hits[kind] || []).filter(t => now - t < 60000));
  if (w.length >= perMinute) return false;
  w.push(now);
  return true;
}
// NOTE: there is deliberately no per-IP lockout. On a shared (school) network it would let
// anyone lock the developer out just by spamming wrong keys. A long random ANNOUNCE_KEY is what
// stops guessing; per-connection throttling below just makes guessing slow and noisy.

/* ---------- server ---------- */
const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("access-terminal relay: ok\n");        // health check for Render
});
const wss = new WebSocketServer({ server, path: "/ws", maxPayload: 8 * 1024 });

const send = (ws, obj) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); };

wss.on("connection", (ws, req) => {
  ws.ip = ipOf(req);
  ws.isAlive = true;
  ws.hits = {};
  ws.room = "general";
  ws.name = "Guest";
  ws.on("pong", () => { ws.isAlive = true; });

  ws.on("message", raw => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (!msg || typeof msg !== "object") return;

    if (msg.type === "join") {
      ws.room = cleanLine(msg.room, LIMITS.room) || "general";
      ws.name = cleanLine(msg.name, LIMITS.name) || "Guest";
      send(ws, { type: "announcement_history", items: history });
      return;
    }

    if (msg.type === "chat") {
      if (!allow(ws, "chat", 40)) return;
      const text = cleanLine(msg.text, LIMITS.chat);
      if (!text) return;
      const out = { type: "chat", text, name: cleanLine(msg.name, LIMITS.name) || ws.name };
      for (const c of wss.clients) if (c !== ws && c.room === ws.room) send(c, out);
      return;
    }

    if (msg.type === "announce") {
      if (!allow(ws, "announce", 10)) { send(ws, { type: "announce_error", text: "Slow down — too many attempts." }); return; }
      if (!keyOk(msg.key)) {
        ws.badKeys = (ws.badKeys || 0) + 1;
        send(ws, { type: "announce_error", text: "Wrong developer key — announcement rejected." });
        if (ws.badKeys >= 5) ws.terminate();          // drop connections that keep guessing
        return;
      }
      const text = cleanText(msg.text, LIMITS.announce);
      if (!text) return;
      const item = {
        id: Date.now().toString(36) + crypto.randomBytes(3).toString("hex"),
        name: cleanLine(msg.name, LIMITS.name) || "Developer",
        text,
        time: Date.now()
      };
      history.push(item);
      history = history.slice(-MAX_HISTORY);
      saveHistory();
      const out = Object.assign({ type: "announcement" }, item);
      for (const c of wss.clients) send(c, out);   // everyone, every room (including the poster)
      return;
    }
  });
});

/* drop dead connections (also keeps Render's proxy from idling the socket out) */
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, 30000).unref();

server.listen(PORT, () => console.log(`relay listening on :${PORT}  (ws path /ws)`));

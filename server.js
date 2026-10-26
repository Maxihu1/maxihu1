// Maxihu1 website server: static site + sign up / login accounts.
// No npm packages needed. Requires Node 22.13 or newer.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "maxihu1.db");
const PUBLIC = path.join(__dirname, "public");
const MIN_USER = 3, MAX_USER = 24, MIN_PASS = 8, MAX_PASS = 64;
const SESSION_DAYS = 30;
const SECURE = process.env.NODE_ENV === "production";

const db = new DatabaseSync(DB_FILE);
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    username_lc TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
`);
const q = {
  findUser: db.prepare("SELECT * FROM users WHERE username_lc = ?"),
  addUser: db.prepare("INSERT INTO users (username, username_lc, password_hash, created_at) VALUES (?,?,?,?)"),
  addSession: db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)"),
  getSession: db.prepare(`SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id
                          WHERE s.token_hash = ? AND s.expires_at > ?`),
  delSession: db.prepare("DELETE FROM sessions WHERE token_hash = ?"),
  purge: db.prepare("DELETE FROM sessions WHERE expires_at <= ?"),
};
setInterval(() => q.purge.run(Date.now()), 3600e3).unref();

// ---- passwords: scrypt with a random salt per user ----
const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k))));
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return `${salt.toString("hex")}:${(await scrypt(pw, salt)).toString("hex")}`;
}
async function checkPassword(pw, stored) {
  const [s, h] = stored.split(":");
  const got = await scrypt(pw, Buffer.from(s, "hex"));
  const want = Buffer.from(h, "hex");
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
let DUMMY; hashPassword("not-a-real-password").then((h) => (DUMMY = h));

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

// ---- helpers ----
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
function sessionCookie(token, maxAge) {
  return `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${SECURE ? "; Secure" : ""}`;
}
function send(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json/i.test(req.headers["content-type"] || "")) return reject({ status: 415, msg: "Bad request." });
    let size = 0, chunks = [];
    req.on("data", (c) => { size += c.length; if (size > 2048) { reject({ status: 413, msg: "Too much data." }); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch { reject({ status: 400, msg: "Bad request." }); } });
    req.on("error", () => reject({ status: 400, msg: "Bad request." }));
  });
}
const hits = new Map();
function limited(req, max, windowMs) {
  const key = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "") .split(",")[0].trim() + req.url;
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) return true;
  arr.push(now); hits.set(key, arr); return false;
}
setInterval(() => hits.clear(), 3600e3).unref();

function validate(b) {
  const username = typeof b.username === "string" ? b.username.trim() : "";
  const password = typeof b.password === "string" ? b.password : "";
  if (username.length < MIN_USER) return { error: `Username must be at least ${MIN_USER} characters.` };
  if (username.length > MAX_USER) return { error: `Username can be at most ${MAX_USER} characters.` };
  if (!/^[A-Za-z0-9_.-]+$/.test(username)) return { error: "Username can only use letters, numbers, _ . and -" };
  if (password.length < MIN_PASS) return { error: `Password must be at least ${MIN_PASS} characters.` };
  if (password.length > MAX_PASS) return { error: `Password can be at most ${MAX_PASS} characters.` };
  return { username, password };
}
function newSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  q.addSession.run(sha(token), userId, Date.now() + SESSION_DAYS * 864e5);
  return sessionCookie(token, SESSION_DAYS * 86400);
}

// ---- API ----
async function api(req, res, pathname) {
  try {
    if (pathname === "/api/me" && req.method === "GET") {
      const t = parseCookies(req).session;
      const u = t && q.getSession.get(sha(t), Date.now());
      return send(res, 200, { username: u ? u.username : null });
    }
    if (req.method !== "POST") return send(res, 404, { error: "Not found." });

    if (pathname === "/api/logout") {
      const t = parseCookies(req).session;
      if (t) q.delSession.run(sha(t));
      return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
    }
    if (pathname === "/api/signup" || pathname === "/api/login") {
      if (limited(req, 10, 15 * 60e3)) return send(res, 429, { error: "Too many tries. Please wait a few minutes and try again." });
      const body = await readJson(req);
      if (pathname === "/api/signup") {
        const v = validate(body);
        if (v.error) return send(res, 400, { error: v.error });
        if (q.findUser.get(v.username.toLowerCase())) return send(res, 409, { error: "That username is taken. Try another one." });
        const hash = await hashPassword(v.password);
        let id;
        try { id = q.addUser.run(v.username, v.username.toLowerCase(), hash, Date.now()).lastInsertRowid; }
        catch { return send(res, 409, { error: "That username is taken. Try another one." }); }
        return send(res, 200, { username: v.username }, { "Set-Cookie": newSession(id) });
      }
      const username = typeof body.username === "string" ? body.username.trim() : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (!username || !password || password.length > MAX_PASS) return send(res, 401, { error: "Wrong username or password." });
      const user = q.findUser.get(username.toLowerCase());
      const ok = await checkPassword(password, user ? user.password_hash : DUMMY);
      if (!user || !ok) return send(res, 401, { error: "Wrong username or password." });
      return send(res, 200, { username: user.username }, { "Set-Cookie": newSession(user.id) });
    }
    return send(res, 404, { error: "Not found." });
  } catch (e) {
    if (e && e.status) return send(res, e.status, { error: e.msg });
    console.error(e);
    return send(res, 500, { error: "Something went wrong. Try again." });
  }
}

// ---- static files ----
const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".png": "image/png", ".jpg": "image/jpeg",
  ".svg": "image/svg+xml", ".mp4": "video/mp4", ".ico": "image/x-icon", ".json": "application/json", ".sb3": "application/octet-stream" };
function serveStatic(req, res, pathname) {
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405); return res.end(); }
  let rel = decodeURIComponent(pathname);
  if (rel.endsWith("/")) rel += "index.html";
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end("Forbidden"); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("Not found"); }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(file).toLowerCase()] || "application/octet-stream", "Content-Length": st.size });
    if (req.method === "HEAD") return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

http.createServer((req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  const pathname = new URL(req.url, "http://x").pathname;
  if (pathname.startsWith("/api/")) return api(req, res, pathname);
  serveStatic(req, res, pathname);
}).listen(PORT, () => console.log(`Maxihu1 site running at http://localhost:${PORT}`));

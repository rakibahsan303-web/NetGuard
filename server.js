// NetGuard Pro bridge server (Express). Receives actions from the web app, logs in to the router,
// keeps the session token, and runs the router request defined by the app's templates.
//
// Environment variables
//   BRIDGE_KEY         required  secret the app sends in the X-Bridge-Key header
//   ALLOWED_TARGETS    required  routers the bridge may contact, as host:port (comma separated)
//   ROUTER_PASSWORD    optional  router admin password, used when the app doesn't send one
//   ALLOW_ORIGIN       optional  your frontend's address, e.g. https://yourapp.netlify.app (default: any)
//   ALLOW_INSECURE_TLS optional  set to 1 if the router uses a self-signed HTTPS certificate
const express = require("express");
const cors = require("cors");
const http = require("http");
const https = require("https");

const KEY = process.env.BRIDGE_KEY;
const ALLOWED = (process.env.ALLOWED_TARGETS || "").split(",").map(s => s.trim()).filter(Boolean);
if (!KEY || !ALLOWED.length) {
  console.error("Set BRIDGE_KEY and ALLOWED_TARGETS (host:port, comma separated) before starting.");
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: "100kb" }));
app.use(cors({ origin: process.env.ALLOW_ORIGIN || "*", allowedHeaders: ["Content-Type", "X-Bridge-Key"] }));

const tokens = new Map(); // session tokens, one per router and username
const ACTIONS = ["login", "status", "block", "unblock", "wifi"];

// {{name}} placeholders: JSON-escaped in JSON bodies, URL-encoded in paths and form bodies
function fill(str, vars, mode) {
  return String(str ?? "").replace(/\{\{(\w+)\}\}/g, (_, k) => {
    const v = String(vars[k] ?? "");
    return mode === "json" ? JSON.stringify(v).slice(1, -1) : mode === "url" ? encodeURIComponent(v) : v;
  });
}

function extractToken(res, spec) {
  if (!spec) return "";
  let v = "";
  if (spec.from === "header") {
    const h = Object.entries(res.headers || {}).find(([k]) => k.toLowerCase() === String(spec.name || "").toLowerCase());
    v = h ? String(h[1]) : "";
  } else if (spec.from === "json") {
    try { v = String(String(spec.path || "").split(".").reduce((o, k) => o?.[k], JSON.parse(res.body)) ?? ""); } catch (e) {}
  } else v = String(res.body || "");
  if (spec.regex) { const m = new RegExp(spec.regex).exec(v); v = m ? (m[1] ?? m[0]) : ""; }
  return v;
}

function sendRequest(base, path, method, headers, body) {
  return new Promise((resolve, reject) => {
    const b = new URL(base), u = new URL(path, b);
    if (u.origin !== b.origin) return reject(new Error("Invalid path"));
    const h = { ...headers };
    if (body) h["Content-Length"] = Buffer.byteLength(body);
    const lib = u.protocol === "https:" ? https : http;
    const r = lib.request(u, { method, headers: h, timeout: 15000, rejectUnauthorized: process.env.ALLOW_INSECURE_TLS !== "1" }, resp => {
      let data = ""; resp.on("data", c => data += c);
      resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: data }));
    });
    r.on("error", reject);
    r.on("timeout", () => r.destroy(new Error("Router timed out")));
    if (body) r.write(body);
    r.end();
  });
}

async function run(action, router, templates, extra, retried = false) {
  const t = templates[action];
  if (!t) throw new Error(`No '${action}' template was sent`);
  const base = `${router.https ? "https" : "http"}://${router.host}:${router.port}`;
  const key = `${base}|${router.adminUser || ""}`;
  if (action !== "login" && action !== "status" && !tokens.has(key) && templates.login && !retried) await run("login", router, templates, {}, true);

  const vars = { ...extra, ip: router.host, port: router.port, adminUser: router.adminUser || "admin",
    adminPass: router.password || process.env.ROUTER_PASSWORD || "", token: tokens.get(key) || "" };
  const bt = t.bodyType || "json", mode = bt === "json" ? "json" : bt === "form" ? "url" : "raw";
  const headers = {};
  Object.entries(t.headers || {}).forEach(([k, v]) => headers[k] = fill(v, vars, "raw"));
  if (!headers["Content-Type"] && bt !== "raw") headers["Content-Type"] = bt === "json" ? "application/json" : "application/x-www-form-urlencoded";
  const method = String(t.method || "GET").toUpperCase();
  const res = await sendRequest(base, fill(t.path, vars, "url"), method, headers, method === "GET" || !t.body ? undefined : fill(t.body, vars, mode));

  if ((res.status === 401 || res.status === 403) && action !== "login" && templates.login && !retried) {
    tokens.delete(key);
    return run(action, router, templates, extra, true);
  }
  const ok = res.status >= 200 && res.status < 300 && (!t.successRegex || new RegExp(t.successRegex).test(res.body));
  let tokenReceived = false;
  if (action === "login" && ok) { const tok = extractToken(res, t.token); if (tok) { tokens.set(key, tok); tokenReceived = true; } }
  return { ok, status: res.status, tokenReceived, body: String(res.body).slice(0, 1000) };
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/api/run", async (req, res) => {
  if (req.get("x-bridge-key") !== KEY) return res.status(401).json({ error: "Wrong bridge API key" });
  try {
    const { action, vars = {}, router = {}, templates = {} } = req.body || {};
    if (!ACTIONS.includes(action)) return res.status(400).json({ error: "Unknown action" });
    if (!router.host || !router.port) return res.status(400).json({ error: "Router IP and port are required" });
    if (!ALLOWED.includes(`${router.host}:${router.port}`)) return res.status(403).json({ error: "That router isn't in ALLOWED_TARGETS" });
    res.json(await run(action, router, templates, vars));
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.listen(process.env.PORT || 8080, () => console.log("NetGuard bridge listening"));

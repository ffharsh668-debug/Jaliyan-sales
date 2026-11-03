require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
app.use(express.static("public"));

const supabaseReady = !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY);
const db = supabaseReady ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
}) : null;
const SESSION_SECRET = process.env.SESSION_SECRET || "";
function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function verifySession(token) {
  if (!SESSION_SECRET || !token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest();
  let actual;
  try { actual = Buffer.from(sig, "base64url"); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload.user;
  } catch { return null; }
}
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const orderLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });

function needDb(req, res, next) {
  if (!db) return res.status(503).json({ error: "Database setup required. Configure Supabase environment variables first." });
  next();
}
function session(req) {
  return verifySession(req.cookies.js_session);
}
function auth(req, res, next) {
  const s = session(req);
  if (!s) return res.status(401).json({ error: "Please enter your numeric access code." });
  req.user = s; next();
}
function admin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only." });
  next();
}
function numericCode(code) {
  return typeof code === "string" && /^[A-Za-z0-9@]{6,12}$/.test(code);
}


app.post("/api/login", loginLimiter, needDb, async (req, res) => {
  const code = String(req.body.code || "");
  if (!numericCode(code)) return res.status(400).json({ error: "Enter your numeric code." });
  let role = null, customer = null;
  if (process.env.ADMIN_CODE && code === process.env.ADMIN_CODE) {
    role = "admin";
  } else {
    const { data, error } = await db.from("customers").select("id,display_name,access_code_hash,active").eq("active", true);
    if (error) return res.status(500).json({ error: "Could not check customer code." });
    for (const c of (data || [])) {
      if (await bcrypt.compare(code, c.access_code_hash)) { customer = c; break; }
    }
    if (customer) role = "customer";
  }
  if (!role) return res.status(401).json({ error: "Invalid code. Please check and try again." });
  if (!SESSION_SECRET) return res.status(503).json({ error: "Session secret is not configured." });
  const user = role === "admin" ? { role } : { role, customerId: customer.id, displayName: customer.display_name };
  const token = signSession({ user, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  res.cookie("js_session", token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.json({ role, displayName: customer?.display_name || "Admin" });
});
app.post("/api/logout", (req, res) => {
  res.clearCookie("js_session", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" }); res.json({ ok: true });
});
app.get("/api/me", auth, (req, res) => res.json({ role: req.user.role, displayName: req.user.displayName || "Admin" }));

app.get("/api/products", needDb, auth, async (req, res) => {
  const { data, error } = await db.from("products").select("id,name,description,price,active,created_at").eq("active", true).order("name");
  if (error) {
  console.error("PRODUCTS ERROR:", error);
  return res.status(500).json({
    error: "Could not load products.",
    details: error.message
  });
}
  res.json(data);
});
app.post("/api/products", needDb, auth, admin, async (req, res) => {
  const { name, description = "", price } = req.body;
  if (!name || !Number.isFinite(Number(price)) || Number(price) < 0) return res.status(400).json({ error: "Valid product name and price required." });
  const { data, error } = await db.from("products").insert({ name: String(name).trim(), description: String(description), price: Number(price), active: true }).select().single();
  if (error) return res.status(500).json({ error: "Could not save product." });
  res.json(data);
});
app.get("/api/customers", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db.from("customers").select("id,display_name,active,created_at").order("display_name");
  if (error) return res.status(500).json({ error: "Could not load customers." });
  res.json(data);
});
app.post("/api/customers", needDb, auth, admin, async (req, res) => {
  const { display_name, code } = req.body;
  if (!display_name || !numericCode(String(code || ""))) return res.status(400).json({ error: "Name and 6–12 digit numeric code required." });
  const hash = await bcrypt.hash(String(code), 12);
  const { data, error } = await db.from("customers").insert({ display_name: String(display_name).trim(), access_code_hash: hash, active: true }).select("id,display_name,active,created_at").single();
  if (error) return res.status(400).json({ error: "Could not create customer. Code may already be used." });
  res.json(data);
});
app.post("/api/orders", needDb, auth, orderLimiter, async (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Customer account required." });
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  if (!items.length || items.length > 50) return res.status(400).json({ error: "Choose at least one item." });
  const { data: products, error: pe } = await db.from("products").select("id,name,price").eq("active", true);
  if (pe) return res.status(500).json({ error: "Could not validate products." });
  const pmap = new Map(products.map(p => [p.id, p]));
  let total = 0;
  const safeItems = [];
  for (const i of items) {
    const p = pmap.get(i.product_id), qty = Number(i.quantity);
    if (!p || !Number.isInteger(qty) || qty < 1 || qty > 10000) return res.status(400).json({ error: "Invalid product or quantity." });
    total += Number(p.price) * qty;
    safeItems.push({ product_id: p.id, name: p.name, unit_price: Number(p.price), quantity: qty });
  }
  const { data: order, error } = await db.from("orders").insert({ customer_id: req.user.customerId, items: safeItems, total, status: "pending", editable_until: new Date(Date.now() + 5 * 60 * 1000).toISOString() }).select().single();
  if (error) return res.status(500).json({ error: "Could not save order." });
  notifyAdmin(order).catch(() => {});
  res.json(order);
});
app.delete("/api/orders/:id", needDb, auth, async (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Customer account required." });
  const { data: order, error } = await db.from("orders").select("id,customer_id,status,editable_until").eq("id", req.params.id).single();
  if (error || !order || order.customer_id !== req.user.customerId) return res.status(404).json({ error: "Order not found." });
  if (order.status !== "pending" || Date.now() > new Date(order.editable_until).getTime()) return res.status(403).json({ error: "The 5-minute delete window has ended or admin has handled this order." });
  const { error: de } = await db.from("orders").delete().eq("id", order.id);
  if (de) return res.status(500).json({ error: "Could not delete order." });
  res.json({ ok: true });
});
app.get("/api/orders", needDb, auth, async (req, res) => {
  let q = db.from("orders").select("id,customer_id,items,total,status,editable_until,created_at,updated_at,customers(display_name)").order("created_at", { ascending: false }).limit(200);
  if (req.user.role === "customer") q = db.from("orders").select("id,items,total,status,editable_until,created_at,updated_at").eq("customer_id", req.user.customerId).order("created_at", { ascending: false }).limit(100);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: "Could not load orders." });
  res.json(data);
});
app.patch("/api/orders/:id/status", needDb, auth, admin, async (req, res) => {
  const status = req.body.status;
  if (!["accepted", "cancelled"].includes(status)) return res.status(400).json({ error: "Invalid status." });
  const { data, error } = await db.from("orders").update({ status, updated_at: new Date().toISOString() }).eq("id", req.params.id).eq("status", "pending").select().single();
  if (error || !data) return res.status(400).json({ error: "Order not found or already handled." });
  res.json(data);
});
app.get("/api/ledger", needDb, auth, async (req, res) => {
  let q = db.from("ledger_entries").select("id,customer_id,amount,note,created_at,customers(display_name)").order("created_at", { ascending: false }).limit(500);
  if (req.user.role === "customer") q = db.from("ledger_entries").select("id,amount,note,created_at").eq("customer_id", req.user.customerId).order("created_at", { ascending: false }).limit(200);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: "Could not load ledger." });
  res.json(data);
});
app.post("/api/ledger", needDb, auth, admin, async (req, res) => {
  const { customer_id, amount, note = "" } = req.body;
  if (!customer_id || !Number.isFinite(Number(amount)) || Number(amount) === 0) return res.status(400).json({ error: "Customer and non-zero amount required." });
  const { data, error } = await db.from("ledger_entries").insert({ customer_id, amount: Number(amount), note: String(note), created_at: new Date().toISOString() }).select().single();
  if (error) return res.status(500).json({ error: "Could not save entry." });
  res.json(data);
});
app.get("/api/health", (req, res) => res.json({ app: "JALIYAAN SALES", databaseConfigured: supabaseReady }));

async function notifyAdmin(order) {
  const to = process.env.ADMIN_WHATSAPP_NUMBER, token = process.env.WHATSAPP_TOKEN, phoneId = process.env.WHATSAPP_PHONE_NUMBER_ID;
  if (!to || !token || !phoneId) return;
  const version = process.env.WHATSAPP_API_VERSION || "v23.0";
  await fetch(`https://graph.facebook.com/${version}/${phoneId}/messages`, {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ messaging_product: "whatsapp", to, type: "text", text: { body: `JALIYAAN SALES: Aapki website par naya order aaya hai. Order ID: ${order.id}. Total: ₹${order.total}. Admin panel kholkar check karein.` } })
  });
}
if (require.main === module && !process.env.NETLIFY) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`JALIYAAN SALES server running on port ${port}`));
}
module.exports = app;

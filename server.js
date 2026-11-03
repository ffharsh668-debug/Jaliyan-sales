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

const supabaseReady = !!(
  process.env.SUPABASE_URL &&
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const db = supabaseReady
  ? createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY,
      { auth: { persistSession: false, autoRefreshToken: false } }
    )
  : null;

const SESSION_SECRET = process.env.SESSION_SECRET || "";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const orderLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");

  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");

  return `${body}.${sig}`;
}

function verifySession(token) {
  if (!SESSION_SECRET || !token || !token.includes(".")) return null;

  const [body, sig] = token.split(".");

  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest();

  let actual;

  try {
    actual = Buffer.from(sig, "base64url");
  } catch {
    return null;
  }

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    );

    if (!payload.exp || payload.exp < Date.now()) return null;

    return payload.user;
  } catch {
    return null;
  }
}

function needDb(req, res, next) {
  if (!db) {
    return res.status(503).json({
      error: "Database is not configured."
    });
  }

  next();
}

function auth(req, res, next) {
  const user = verifySession(req.cookies.js_session);

  if (!user) {
    return res.status(401).json({
      error: "Please login first."
    });
  }

  req.user = user;
  next();
}

function admin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Admin only."
    });
  }

  next();
}

function numericCode(code) {
  return (
    typeof code === "string" &&
    /^[A-Za-z0-9@]{6,12}$/.test(code)
  );
}

function validAmount(value, allowZero = false) {
  const n = Number(value);

  return (
    Number.isFinite(n) &&
    (allowZero ? n >= 0 : n > 0)
  );
}

async function audit(req, action, entityType, entityId = "", details = {}) {
  try {
    await db.from("audit_logs").insert({
      actor_role: req?.user?.role || "admin",
      actor_id: req?.user?.adminId || null,
      actor_name: req?.user?.displayName || "Admin",
      action,
      entity_type: entityType,
      entity_id: String(entityId),
      details
    });
  } catch (error) {
    console.error("AUDIT ERROR:", error.message);
  }
}


// ==========================================
// LOGIN SYSTEM
// ==========================================

app.post("/api/login", loginLimiter, needDb, async (req, res) => {
  const code = String(req.body.code || "");

  if (!numericCode(code)) {
    return res.status(400).json({
      error: "Enter a valid access code."
    });
  }

  let role = null;
  let customer = null;
  let adminUser = null;

  if (process.env.ADMIN_CODE && code === process.env.ADMIN_CODE) {
    role = "admin";
    adminUser = { id: null, display_name: "Main Admin" };
  } else {
    const { data: adminCodes, error: adminError } = await db
      .from("admin_codes")
      .select("id,display_name,access_code_hash")
      .eq("active", true);

    if (adminError) {
      return res.status(500).json({ error: "Could not check admin codes." });
    }

    for (const a of adminCodes || []) {
      if (await bcrypt.compare(code, a.access_code_hash)) {
        adminUser = a;
        role = "admin";
        break;
      }
    }

    if (!role) {
      const { data, error } = await db
        .from("customers")
        .select("id,display_name,access_code_hash,active")
        .eq("active", true);

      if (error) {
        return res.status(500).json({ error: "Could not check customer code." });
      }

      for (const c of data || []) {
        if (await bcrypt.compare(code, c.access_code_hash)) {
          customer = c;
          break;
        }
      }

      if (customer) role = "customer";
    }
  }

  if (!role) {
    return res.status(401).json({
      error: "Invalid access code."
    });
  }

  if (!SESSION_SECRET) {
    return res.status(503).json({
      error: "Session secret is not configured."
    });
  }

  if (role === "customer" && customer?.id) {
    const { error: loginUpdateError } = await db.from("customers").update({ last_login_at: new Date().toISOString() }).eq("id", customer.id);
    if (loginUpdateError) console.error("CUSTOMER LAST LOGIN UPDATE:", loginUpdateError.message);
  }

  const user = role === "admin"
    ? {
        role,
        adminId: adminUser?.id || null,
        displayName: adminUser?.display_name || "Main Admin"
      }
    : {
        role,
        customerId: customer.id,
        displayName: customer.display_name
      };

  const token = signSession({
    user,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000
  });

  res.cookie("js_session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 24 * 60 * 60 * 1000
  });

  res.json({
    role,
    displayName: user.displayName
  });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("js_session", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  });

  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    role: req.user.role,
    displayName: req.user.displayName || "Admin"
  });
});


// ==========================================
// PRODUCTS
// ==========================================

app.get("/api/products", needDb, auth, async (req, res) => {
  const { data, error } = await db
    .from("products")
    .select("*")
    .eq("active", true)
    .order("name");

  if (error) {
    return res.status(500).json({
      error: "Could not load products."
    });
  }

  res.json(data);
});

app.post("/api/products", needDb, auth, admin, async (req, res) => {
  const {
    name,
    description = "",
    price,
    sku = null,
    category = "Tobacco",
    unit = "piece",
    cost_price = 0,
    stock_quantity = 0,
    low_stock_threshold = 0,
    brand = "",
    pack_size = "",
    barcode = ""
  } = req.body;

  if (
    !name ||
    !validAmount(price, true) ||
    !validAmount(cost_price, true) ||
    !validAmount(stock_quantity, true) ||
    !validAmount(low_stock_threshold, true)
  ) {
    return res.status(400).json({
      error: "Invalid product details."
    });
  }

  const { data, error } = await db
    .from("products")
    .insert({
      name: String(name).trim(),
      description: String(description),
      price: Number(price),
      sku,
      category,
      unit,
      cost_price: Number(cost_price),
      stock_quantity: Number(stock_quantity),
      low_stock_threshold: Number(low_stock_threshold),
      brand,
      pack_size,
      barcode,
      active: true
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not save product.",
      details: error.message
    });
  }

  await audit(req, "product_created", "product", data.id);

  res.json(data);
});

app.patch("/api/products/:id", needDb, auth, admin, async (req, res) => {
  const allowed = [
    "name",
    "description",
    "price",
    "sku",
    "category",
    "unit",
    "cost_price",
    "stock_quantity",
    "low_stock_threshold",
    "brand",
    "pack_size",
    "barcode",
    "active"
  ];

  const updates = {};

  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      updates[key] = req.body[key];
    }
  }

  if (!Object.keys(updates).length) {
    return res.status(400).json({
      error: "Nothing to update."
    });
  }

  const { data, error } = await db
    .from("products")
    .update(updates)
    .eq("id", req.params.id)
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not update product."
    });
  }

  await audit(req, "product_updated", "product", data.id);

  res.json(data);
});

app.delete("/api/products/:id", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("products")
    .update({ active: false })
    .eq("id", req.params.id)
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not deactivate product."
    });
  }

  res.json({ success: true, product: data });
});
// ==========================================
// CUSTOMERS
// ==========================================

app.get("/api/admin-codes", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db.from("admin_codes")
    .select("id,display_name,active,created_at")
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ error: "Could not load admin codes." });
  res.json(data || []);
});

app.post("/api/admin-codes", needDb, auth, admin, async (req, res) => {
  const displayName = String(req.body.display_name || "").trim();
  const code = String(req.body.code || "");
  if (!displayName || !numericCode(code)) {
    return res.status(400).json({ error: "Admin name and valid 6-12 character code required." });
  }
  if (process.env.ADMIN_CODE && code === process.env.ADMIN_CODE) {
    return res.status(400).json({ error: "This code is already used by the main admin." });
  }
  const hash = await bcrypt.hash(code, 12);
  const { data, error } = await db.from("admin_codes")
    .insert({ display_name: displayName, access_code_hash: hash, active: true })
    .select("id,display_name,active,created_at").single();
  if (error) return res.status(400).json({ error: "Could not create admin code. Code may already exist." });
  await audit(req, "admin_code_created", "admin_code", data.id, { display_name: displayName });
  res.json(data);
});

app.patch("/api/admin-codes/:id", needDb, auth, admin, async (req, res) => {
  const active = req.body.active;
  if (typeof active !== "boolean") return res.status(400).json({ error: "Active status required." });
  const { data, error } = await db.from("admin_codes")
    .update({ active }).eq("id", req.params.id)
    .select("id,display_name,active,created_at").single();
  if (error) return res.status(500).json({ error: "Could not update admin code." });
  await audit(req, active ? "admin_code_activated" : "admin_code_deactivated",
    "admin_code", data.id, { display_name: data.display_name });
  res.json(data);
});

app.get("/api/admin-history", needDb, auth, admin, async (req, res) => {
  const [customersResult, ledgerResult, logsResult] = await Promise.all([
    db.from("customers").select("id,display_name,active,created_at").order("display_name"),
    db.from("ledger_entries").select("id,customer_id,amount,note,created_at")
      .order("created_at", { ascending: false }).limit(2000),
    db.from("audit_logs").select("*").order("created_at", { ascending: false }).limit(500)
  ]);
  if (customersResult.error || ledgerResult.error || logsResult.error) {
    return res.status(500).json({ error: "Could not load admin history." });
  }
  const entries = ledgerResult.data || [];
  const customers = (customersResult.data || []).map(customer => {
    const customerEntries = entries.filter(entry => entry.customer_id === customer.id);
    const balance = customerEntries.reduce((sum, entry) => sum + Number(entry.amount || 0), 0);
    return { ...customer, balance, totalEntries: customerEntries.length, entries: customerEntries };
  });
  res.json({ customers, actions: logsResult.data || [] });
});

app.get("/api/customers", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("customers")
    .select("id,display_name,active,age_verified,created_at,last_login_at")
    .order("display_name");

  if (error) {
    return res.status(500).json({
      error: "Could not load customers."
    });
  }

  res.json(data);
});

app.post("/api/customers", needDb, auth, admin, async (req, res) => {
  const { display_name, code } = req.body;

  if (!display_name || !numericCode(String(code || ""))) {
    return res.status(400).json({
      error: "Name and valid access code required."
    });
  }

  const hash = await bcrypt.hash(String(code), 12);

  const { data, error } = await db
    .from("customers")
    .insert({
      display_name: String(display_name).trim(),
      access_code_hash: hash,
      active: true
    })
    .select("id,display_name,active,created_at")
    .single();

  if (error) {
    return res.status(400).json({
      error: "Could not create customer. Code may already exist."
    });
  }

  await audit(req, "customer_created", "customer", data.id, {
    display_name: data.display_name
  });
  res.json(data);
});


// ==========================================
// ORDERS
// ==========================================

app.post("/api/admin-sales", needDb, auth, admin, async (req, res) => {
  const { customer_id, items, gst_percent = 0 } = req.body;
  const rate = Number(gst_percent);
  if (!customer_id || !Array.isArray(items) || !items.length || items.length > 50 || !Number.isFinite(rate) || rate < 0 || rate > 28) return res.status(400).json({ error: "Customer, items and GST rate from 0 to 28 are required." });
  const { data: customer, error: customerError } = await db.from("customers").select("id").eq("id", customer_id).eq("active", true).single();
  if (customerError || !customer) return res.status(400).json({ error: "Select an active customer." });
  const { data: products, error: productError } = await db.from("products").select("id,name,price").eq("active", true);
  if (productError) return res.status(500).json({ error: "Could not validate products." });
  const productMap = new Map(products.map(p => [p.id, p]));
  let subtotal = 0; const safeItems = [];
  for (const item of items) { const product = productMap.get(item.product_id); const quantity = Number(item.quantity); if (!product || !Number.isInteger(quantity) || quantity < 1 || quantity > 10000) return res.status(400).json({ error: "Invalid product or quantity." }); const line = Number(product.price) * quantity; subtotal += line; safeItems.push({ product_id: product.id, name: product.name, unit_price: Number(product.price), quantity, gst_percent: rate, line_subtotal: line }); }
  const taxAmount = subtotal * rate / 100; const total = subtotal + taxAmount;
  const { data, error } = await db.from("orders").insert({ customer_id, items: safeItems, total, status: "pending", editable_until: new Date().toISOString() }).select().single();
  if (error) return res.status(500).json({ error: "Could not create POS sale.", details: error.message });
  await audit(req, "pos_sale_created", "order", data.id, { customer_id, subtotal, gst_percent: rate, tax_amount: taxAmount, total });
  res.json(data);
});
app.post("/api/orders", needDb, auth, orderLimiter, async (req, res) => {
  if (req.user.role !== "customer") {
    return res.status(403).json({
      error: "Customer account required."
    });
  }

  const items = Array.isArray(req.body.items)
    ? req.body.items
    : [];

  if (!items.length || items.length > 50) {
    return res.status(400).json({
      error: "Choose at least one item."
    });
  }

  const { data: products, error: pe } = await db
    .from("products")
    .select("id,name,price,cost_price")
    .eq("active", true);

  if (pe) {
    return res.status(500).json({
      error: "Could not validate products."
    });
  }

  const productMap = new Map(
    products.map(p => [p.id, p])
  );

  let total = 0;
  const safeItems = [];

  for (const item of items) {
    const product = productMap.get(item.product_id);
    const quantity = Number(item.quantity);

    if (
      !product ||
      !Number.isInteger(quantity) ||
      quantity < 1 ||
      quantity > 10000
    ) {
      return res.status(400).json({
        error: "Invalid product or quantity."
      });
    }

    total += Number(product.price) * quantity;

    safeItems.push({
      product_id: product.id,
      name: product.name,
      unit_price: Number(product.price),
      cost_price: Number(product.cost_price || 0),
      quantity
    });
  }

  const { data: order, error } = await db
    .from("orders")
    .insert({
      customer_id: req.user.customerId,
      items: safeItems,
      total,
      status: "pending",
      editable_until: new Date(
        Date.now() + 5 * 60 * 1000
      ).toISOString()
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not save order."
    });
  }

  notifyAdmin(order).catch(() => {});

  res.json(order);
});

app.delete("/api/orders/:id", needDb, auth, async (req, res) => {
  if (req.user.role !== "customer") {
    return res.status(403).json({
      error: "Customer account required."
    });
  }

  const { data: order, error } = await db
    .from("orders")
    .select("*")
    .eq("id", req.params.id)
    .single();

  if (
    error ||
    !order ||
    order.customer_id !== req.user.customerId
  ) {
    return res.status(404).json({
      error: "Order not found."
    });
  }

  if (
    order.status !== "pending" ||
    Date.now() > new Date(order.editable_until).getTime()
  ) {
    return res.status(403).json({
      error: "Order can no longer be deleted."
    });
  }

  const { error: deleteError } = await db
    .from("orders")
    .delete()
    .eq("id", order.id);

  if (deleteError) {
    return res.status(500).json({
      error: "Could not delete order."
    });
  }

  res.json({ ok: true });
});

app.get("/api/orders", needDb, auth, async (req, res) => {
  let query = db
    .from("orders")
    .select("id,customer_id,items,total,status,editable_until,created_at,updated_at,customers(display_name)")
    .order("created_at", { ascending: false })
    .limit(200);

  if (req.user.role === "customer") {
    query = db
      .from("orders")
      .select("id,items,total,status,editable_until,created_at,updated_at")
      .eq("customer_id", req.user.customerId)
      .order("created_at", { ascending: false })
      .limit(100);
  }

  const { data, error } = await query;

  if (error) {
    return res.status(500).json({
      error: "Could not load orders."
    });
  }

  res.json(data);
});

app.patch("/api/orders/:id/status", needDb, auth, admin, async (req, res) => {
  const status = req.body.status;
  if (!["accepted", "cancelled"].includes(status)) return res.status(400).json({ error: "Invalid status." });
  const { data: order, error: orderError } = await db.from("orders").select("*").eq("id", req.params.id).eq("status", "pending").single();
  if (orderError || !order) return res.status(400).json({ error: "Order not found or already handled." });
  const { data: claimed, error: claimError } = await db.from("orders").update({ status, updated_at: new Date().toISOString() }).eq("id", order.id).eq("status", "pending").select().single();
  if (claimError || !claimed) return res.status(400).json({ error: "Order not found or already handled." });
  const changed = [];
  const movementIds = [];
  const rollback = async () => {
    for (const item of changed.reverse()) await db.from("products").update({ stock_quantity: item.before }).eq("id", item.id).eq("stock_quantity", item.after);
    if (movementIds.length) await db.from("inventory_movements").delete().in("id", movementIds);
    await db.from("orders").update({ status: "pending", updated_at: new Date().toISOString() }).eq("id", order.id).eq("status", "accepted");
  };
  if (status === "accepted") {
    const items = Array.isArray(order.items) ? order.items : [];
    for (const item of items) {
      const qty = Number(item.quantity);
      if (!item.product_id || !Number.isInteger(qty) || qty < 1) { await rollback(); return res.status(400).json({ error: "Order contains invalid item details." }); }
      const { data: product, error: productError } = await db.from("products").select("id,name,stock_quantity").eq("id", item.product_id).single();
      if (productError || !product) { await rollback(); return res.status(400).json({ error: "An ordered product could not be found." }); }
      const before = Number(product.stock_quantity || 0);
      const after = before - qty;
      if (after < 0) { await rollback(); return res.status(400).json({ error: "Insufficient stock for " + product.name + ". Available: " + before + ", required: " + qty }); }
      const { data: updated, error: stockError } = await db.from("products").update({ stock_quantity: after }).eq("id", product.id).eq("stock_quantity", before).select("id").maybeSingle();
      if (stockError || !updated) { await rollback(); return res.status(409).json({ error: "Stock changed while processing. Refresh inventory and try again." }); }
      changed.push({ id: product.id, before, after });
      const { data: movement, error: movementError } = await db.from("inventory_movements").insert({ product_id: product.id, movement_type: "adjustment_out", quantity: qty, notes: "Sale accepted - Order: " + order.id }).select("id").single();
      if (movementError) { await rollback(); return res.status(500).json({ error: "Stock changed but movement record failed. Please check inventory." }); }
      movementIds.push(movement.id);
    }
    const { error: ledgerError } = await db.from("ledger_entries").insert({ customer_id: order.customer_id, amount: Number(order.total), note: "Order sale: " + order.id });
    if (ledgerError) { await rollback(); return res.status(500).json({ error: "Stock updated but customer ledger could not be updated. Please verify before retrying." }); }
  }
  await audit(req, "order_status_updated", "order", claimed.id, { status: claimed.status, customer_id: claimed.customer_id });
  const orderMessage = status === "accepted" ? "Your order has been accepted. Stock and account ledger have been updated." : "Your order has been cancelled.";
  const { error: inboxError } = await db.from("inbox_messages").insert({ message_type: "personal", recipient_customer_id: claimed.customer_id, body: orderMessage });
  if (inboxError) console.error("ORDER INBOX ERROR:", inboxError.message);
  res.json(claimed);
});

// ==========================================
// LEDGER
// ==========================================

app.get("/api/ledger", needDb, auth, async (req, res) => {
  let query = db
    .from("ledger_entries")
    .select("id,customer_id,amount,note,created_at,customers(display_name)")
    .order("created_at", { ascending: false })
    .limit(500);

  if (req.user.role === "customer") {
    query = db
      .from("ledger_entries")
      .select("id,amount,note,created_at")
      .eq("customer_id", req.user.customerId)
      .order("created_at", { ascending: false })
      .limit(200);
  }

  const { data, error } = await query;

  if (error) {
    return res.status(500).json({
      error: "Could not load ledger."
    });
  }

  res.json(data);
});

app.post("/api/ledger", needDb, auth, admin, async (req, res) => {
  const { customer_id, amount, note = "" } = req.body;

  if (
    !customer_id ||
    !Number.isFinite(Number(amount)) ||
    Number(amount) === 0
  ) {
    return res.status(400).json({
      error: "Customer and non-zero amount required."
    });
  }

  const { data, error } = await db
    .from("ledger_entries")
    .insert({
      customer_id,
      amount: Number(amount),
      note: String(note)
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not save ledger entry."
    });
  }

  const { data: customer } = await db.from("customers")
    .select("display_name").eq("id", customer_id).single();
  const amountText = Number(amount) > 0
    ? `₹${Number(amount).toFixed(2)} credit hua`
    : `₹${Math.abs(Number(amount)).toFixed(2)} debit hua`;
  const { error: inboxError } = await db.from("inbox_messages").insert({
    message_type: "personal",
    recipient_customer_id: customer_id,
    body: `Account Update: ${amountText}. Note: ${String(note || "Ledger updated")}`
  });
  if (inboxError) console.error("LEDGER INBOX ERROR:", inboxError.message);
  await audit(req, "ledger_entry_created", "ledger", data.id, {
    customer_id, amount: Number(amount), customer_name: customer?.display_name || ""
  });
  res.json(data);
});// ==========================================
// SUPPLIERS
// ==========================================

app.get("/api/suppliers", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("suppliers")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    return res.status(500).json({
      error: "Could not load suppliers."
    });
  }

  res.json(data);
});

app.post("/api/suppliers", needDb, auth, admin, async (req, res) => {
  const {
    name,
    contact_person = "",
    phone = "",
    email = "",
    address = "",
    gstin = "",
    notes = ""
  } = req.body;

  if (!name || !String(name).trim()) {
    return res.status(400).json({
      error: "Supplier name required."
    });
  }

  const { data, error } = await db
    .from("suppliers")
    .insert({
      name: String(name).trim(),
      contact_person,
      phone,
      email,
      address,
      gstin,
      notes
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not add supplier."
    });
  }

  await audit(req, "supplier_created", "supplier", data.id);

  res.json(data);
});

app.patch("/api/suppliers/:id", needDb, auth, admin, async (req, res) => {
  const allowed = [
    "name",
    "contact_person",
    "phone",
    "email",
    "address",
    "gstin",
    "notes",
    "active"
  ];

  const updates = {};

  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      updates[key] = req.body[key];
    }
  }

  const { data, error } = await db
    .from("suppliers")
    .update({
      ...updates,
      updated_at: new Date().toISOString()
    })
    .eq("id", req.params.id)
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not update supplier."
    });
  }

  res.json(data);
});

app.delete("/api/suppliers/:id", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("suppliers")
    .update({
      active: false,
      updated_at: new Date().toISOString()
    })
    .eq("id", req.params.id)
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not deactivate supplier."
    });
  }

  res.json({ success: true, supplier: data });
});


// ==========================================
// PURCHASES
// ==========================================

app.get("/api/purchases", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("purchases")
    .select("*,suppliers(name)")
    .order("purchase_date", { ascending: false })
    .limit(500);

  if (error) {
    return res.status(500).json({
      error: "Could not load purchases."
    });
  }

  res.json(data);
});

app.post("/api/purchases", needDb, auth, admin, async (req, res) => {
  const {
    supplier_id = null,
    invoice_number = "",
    purchase_date,
    items,
    tax_amount = 0,
    other_charges = 0,
    amount_paid = 0,
    notes = ""
  } = req.body;

  if (!Array.isArray(items) || !items.length) {
    return res.status(400).json({
      error: "Purchase items required."
    });
  }

  if (
    !validAmount(tax_amount, true) ||
    !validAmount(other_charges, true) ||
    !validAmount(amount_paid, true)
  ) {
    return res.status(400).json({
      error: "Invalid purchase amounts."
    });
  }

  let subtotal = 0;
  const safeItems = [];

  for (const item of items) {
    const quantity = Number(item.quantity);
    const unitCost = Number(item.unit_cost);

    if (
      !item.product_id ||
      !validAmount(quantity) ||
      !validAmount(unitCost, true)
    ) {
      return res.status(400).json({
        error: "Invalid purchase item."
      });
    }

    const { data: product, error: productError } = await db
      .from("products")
      .select("id,name")
      .eq("id", item.product_id)
      .single();

    if (productError || !product) {
      return res.status(400).json({
        error: "Purchase product not found."
      });
    }

    subtotal += quantity * unitCost;

    safeItems.push({
      product_id: product.id,
      name: product.name,
      quantity,
      unit_cost: unitCost
    });
  }

  const total =
    subtotal + Number(tax_amount) + Number(other_charges);

  const { data, error } = await db
    .from("purchases")
    .insert({
      supplier_id,
      invoice_number,
      purchase_date: purchase_date || new Date().toISOString().slice(0, 10),
      items: safeItems,
      subtotal,
      tax_amount: Number(tax_amount),
      other_charges: Number(other_charges),
      total,
      amount_paid: Number(amount_paid),
      notes,
      status: "draft"
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not save purchase.",
      details: error.message
    });
  }

  await audit(req, "purchase_created", "purchase", data.id);

  res.json(data);
});

app.post("/api/purchases/:id/receive", needDb, auth, admin, async (req, res) => {
  const { data: purchase, error: purchaseError } = await db
    .from("purchases")
    .select("*")
    .eq("id", req.params.id)
    .single();

  if (purchaseError || !purchase) {
    return res.status(404).json({
      error: "Purchase not found."
    });
  }

  if (purchase.status !== "draft") {
    return res.status(400).json({
      error: "Purchase already received or not eligible."
    });
  }

  const items = Array.isArray(purchase.items) ? purchase.items : [];

  for (const item of items) {
    const { data: product, error: productError } = await db
      .from("products")
      .select("stock_quantity,cost_price")
      .eq("id", item.product_id)
      .single();

    if (productError || !product) {
      return res.status(400).json({
        error: "A purchase product could not be found."
      });
    }

    const { error: updateError } = await db
      .from("products")
      .update({
        stock_quantity: Number(product.stock_quantity || 0) + Number(item.quantity),
        cost_price: Number(item.unit_cost)
      })
      .eq("id", item.product_id);

    if (updateError) {
      return res.status(500).json({
        error: "Could not update stock."
      });
    }

    await db.from("inventory_movements").insert({
      product_id: item.product_id,
      movement_type: "purchase_in",
      quantity: Number(item.quantity),
      notes: "Purchase received"
    });
  }

  const { data, error } = await db
    .from("purchases")
    .update({
      status: "received",
      received_at: new Date().toISOString()
    })
    .eq("id", purchase.id)
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Stock received but purchase status could not be updated."
    });
  }

  await audit(req, "purchase_received", "purchase", data.id);

  res.json(data);
});


// ==========================================
// INVENTORY
// ==========================================

app.get("/api/inventory", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("products")
    .select("id,name,sku,stock_quantity,low_stock_threshold")
    .eq("active", true)
    .order("name");

  if (error) {
    return res.status(500).json({
      error: "Could not load inventory."
    });
  }

  res.json(data);
});

app.get("/api/inventory/low-stock", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("products")
    .select("id,name,sku,stock_quantity,low_stock_threshold")
    .eq("active", true)
    .order("stock_quantity");

  if (error) {
    return res.status(500).json({
      error: "Could not load low stock."
    });
  }

  res.json((data || []).filter(p =>
    Number(p.stock_quantity || 0) <= Number(p.low_stock_threshold || 0)
  ));
});

app.get("/api/inventory/movements", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("inventory_movements")
    .select("*,products(name)")
    .order("created_at", { ascending: false })
    .limit(500);

  if (error) {
    return res.status(500).json({
      error: "Could not load inventory movements."
    });
  }

  res.json(data);
});

app.post("/api/inventory/adjust", needDb, auth, admin, async (req, res) => {
  const { product_id, movement_type, quantity, notes = "" } = req.body;

  const allowedTypes = [
    "adjustment_in",
    "adjustment_out",
    "damage",
    "return_in",
    "return_out"
  ];

  if (
    !product_id ||
    !allowedTypes.includes(movement_type) ||
    !Number.isInteger(Number(quantity)) ||
    Number(quantity) < 1
  ) {
    return res.status(400).json({
      error: "Invalid stock adjustment."
    });
  }

  const { data: product, error: productError } = await db
    .from("products")
    .select("id,stock_quantity")
    .eq("id", product_id)
    .single();

  if (productError || !product) {
    return res.status(404).json({
      error: "Product not found."
    });
  }

  const isIn = ["adjustment_in", "return_in"].includes(movement_type);
  const nextStock = Number(product.stock_quantity || 0) +
    (isIn ? Number(quantity) : -Number(quantity));

  if (nextStock < 0) {
    return res.status(400).json({
      error: "Stock cannot become negative."
    });
  }

  const { error: updateError } = await db
    .from("products")
    .update({ stock_quantity: nextStock })
    .eq("id", product_id);

  if (updateError) {
    return res.status(500).json({
      error: "Could not update stock."
    });
  }

  const { data, error } = await db
    .from("inventory_movements")
    .insert({
      product_id,
      movement_type,
      quantity: Number(quantity),
      notes: String(notes)
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Stock changed but movement could not be recorded."
    });
  }

  await audit(req, "inventory_adjusted", "product", product_id, {
    movement_type,
    quantity: Number(quantity)
  });

  res.json(data);
});


// ==========================================
// EXPENSES
// ==========================================
// EXPENSES
// ==========================================

app.get("/api/expenses", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("expenses")
    .select("*")
    .order("expense_date", { ascending: false })
    .limit(500);

  if (error) {
    return res.status(500).json({
      error: "Could not load expenses."
    });
  }

  res.json(data);
});

app.post("/api/expenses", needDb, auth, admin, async (req, res) => {
  const {
    category,
    description = "",
    amount,
    expense_date,
    payment_method = "cash",
    reference_number = "",
    notes = ""
  } = req.body;

  if (!category || !validAmount(amount)) {
    return res.status(400).json({
      error: "Expense category and valid amount required."
    });
  }

  const { data, error } = await db
    .from("expenses")
    .insert({
      category,
      description,
      amount: Number(amount),
      expense_date: expense_date || new Date().toISOString().slice(0, 10),
      payment_method,
      reference_number,
      notes
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not save expense."
    });
  }

  await audit(req, "expense_created", "expense", data.id);

  res.json(data);
});

app.delete("/api/expenses/:id", needDb, auth, admin, async (req, res) => {
  const { error } = await db
    .from("expenses")
    .delete()
    .eq("id", req.params.id);

  if (error) {
    return res.status(500).json({
      error: "Could not delete expense."
    });
  }

  res.json({ success: true });
});


// ==========================================
// CUSTOMER PAYMENTS
// ==========================================

app.get("/api/customer-payments", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("customer_payments")
    .select("*,customers(display_name)")
    .order("payment_date", { ascending: false })
    .limit(500);

  if (error) {
    return res.status(500).json({
      error: "Could not load customer payments."
    });
  }

  res.json(data);
});

app.post("/api/customer-payments", needDb, auth, admin, async (req, res) => {
  const {
    customer_id,
    order_id = null,
    amount,
    payment_method = "cash",
    reference_number = "",
    notes = ""
  } = req.body;

  if (!customer_id || !validAmount(amount)) {
    return res.status(400).json({
      error: "Customer and valid payment amount required."
    });
  }

  const { data, error } = await db
    .from("customer_payments")
    .insert({
      customer_id,
      order_id,
      amount: Number(amount),
      payment_method,
      reference_number,
      notes
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not save customer payment."
    });
  }

  const { error: ledgerError } = await db.from("ledger_entries").insert({
    customer_id,
    amount: -Number(amount),
    note: "Payment received: " + payment_method
  });

  if (ledgerError) {
    return res.status(500).json({ error: "Payment saved but ledger update failed." });
  }

  const { error: inboxError } = await db.from("inbox_messages").insert({
    message_type: "personal",
    recipient_customer_id: customer_id,
    body: `Payment received: ₹${Number(amount).toFixed(2)}. Your account ledger has been updated.`
  });
  if (inboxError) console.error("PAYMENT INBOX ERROR:", inboxError.message);

  await audit(req, "customer_payment_created", "customer_payment", data.id, {
    customer_id, amount: Number(amount), payment_method
  });

  res.json(data);
});


// ==========================================
// SUPPLIER PAYMENTS
// ==========================================

app.get("/api/supplier-payments", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("supplier_payments")
    .select("*,suppliers(name)")
    .order("payment_date", { ascending: false })
    .limit(500);

  if (error) {
    return res.status(500).json({
      error: "Could not load supplier payments."
    });
  }

  res.json(data);
});

app.post("/api/supplier-payments", needDb, auth, admin, async (req, res) => {
  const {
    supplier_id,
    purchase_id = null,
    amount,
    payment_method = "cash",
    reference_number = "",
    notes = ""
  } = req.body;

  if (!supplier_id || !validAmount(amount)) {
    return res.status(400).json({
      error: "Supplier and valid payment amount required."
    });
  }

  const { data, error } = await db
    .from("supplier_payments")
    .insert({
      supplier_id,
      purchase_id,
      amount: Number(amount),
      payment_method,
      reference_number,
      notes
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not save supplier payment."
    });
  }

  if (purchase_id) {
    const { data: purchase } = await db
      .from("purchases")
      .select("amount_paid")
      .eq("id", purchase_id)
      .single();

    if (purchase) {
      await db
        .from("purchases")
        .update({
          amount_paid:
            Number(purchase.amount_paid || 0) + Number(amount)
        })
        .eq("id", purchase_id);
    }
  }

  await audit(req, "supplier_payment_created", "supplier_payment", data.id, {
    supplier_id, amount: Number(amount), payment_method
  });

  res.json(data);
});


// ==========================================
// INBOX SYSTEM
// ==========================================

app.post("/api/inbox/messages", needDb, auth, admin, async (req, res) => {
  const type = String(req.body.message_type || "");
  const body = String(req.body.body || "").trim();

  if (!["group", "personal"].includes(type)) {
    return res.status(400).json({
      error: "Invalid message type."
    });
  }

  if (!body || body.length > 5000) {
    return res.status(400).json({
      error: "Message must be 1-5000 characters."
    });
  }

  let recipientId = null;

  if (type === "personal") {
    const code = String(req.body.customer_code || "");

    if (!numericCode(code)) {
      return res.status(400).json({
        error: "Enter a valid customer code."
      });
    }

    const { data: customers, error } = await db
      .from("customers")
      .select("id,access_code_hash")
      .eq("active", true);

    if (error) {
      return res.status(500).json({
        error: "Could not find customer."
      });
    }

    let matched = null;

    for (const customer of customers || []) {
      if (await bcrypt.compare(code, customer.access_code_hash)) {
        matched = customer;
        break;
      }
    }

    if (!matched) {
      return res.status(404).json({
        error: "Customer code not found."
      });
    }

    recipientId = matched.id;
  }

  const { data, error } = await db
    .from("inbox_messages")
    .insert({
      message_type: type,
      recipient_customer_id: recipientId,
      body
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not send message."
    });
  }

  res.json(data);
});

app.get("/api/inbox/messages", needDb, auth, async (req, res) => {
  if (req.user.role === "admin") {
    const { data, error } = await db
      .from("inbox_messages")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(500);

    if (error) {
      return res.status(500).json({
        error: "Could not load inbox."
      });
    }

    const { data: customers } = await db
      .from("customers")
      .select("id,display_name");

    const customerMap = new Map(
      (customers || []).map(c => [c.id, c.display_name])
    );

    return res.json(
      (data || []).map(m => ({
        ...m,
        recipient_name: m.recipient_customer_id
          ? customerMap.get(m.recipient_customer_id) || "Customer"
          : "All Customers"
      }))
    );
  }

  const customerId = req.user.customerId;

  const { data: group, error: groupError } = await db
    .from("inbox_messages")
    .select("*")
    .eq("message_type", "group")
    .order("created_at", { ascending: false });

  const { data: personal, error: personalError } = await db
    .from("inbox_messages")
    .select("*")
    .eq("message_type", "personal")
    .eq("recipient_customer_id", customerId)
    .order("created_at", { ascending: false });

  if (groupError || personalError) {
    return res.status(500).json({
      error: "Could not load inbox."
    });
  }

  const messages = [
    ...(group || []),
    ...(personal || [])
  ].sort(
    (a, b) =>
      new Date(b.created_at) - new Date(a.created_at)
  );

  const { data: reads } = await db
    .from("inbox_reads")
    .select("message_id,read_at")
    .eq("customer_id", customerId);

  const readMap = new Map(
    (reads || []).map(r => [r.message_id, r.read_at])
  );

  res.json(
    messages.map(m => ({
      ...m,
      is_read: readMap.has(m.id),
      read_at: readMap.get(m.id) || null
    }))
  );
});

app.post("/api/inbox/messages/:id/read", needDb, auth, async (req, res) => {
  if (req.user.role !== "customer") {
    return res.status(403).json({
      error: "Customer account required."
    });
  }

  const { data: message, error } = await db
    .from("inbox_messages")
    .select("*")
    .eq("id", req.params.id)
    .maybeSingle();

  if (error || !message) {
    return res.status(404).json({
      error: "Message not found."
    });
  }

  const allowed =
    message.message_type === "group" ||
    message.recipient_customer_id === req.user.customerId;

  if (!allowed) {
    return res.status(403).json({
      error: "This message is not for you."
    });
  }

  const { error: readError } = await db
    .from("inbox_reads")
    .upsert(
      {
        message_id: message.id,
        customer_id: req.user.customerId
      },
      {
        onConflict: "message_id,customer_id",
        ignoreDuplicates: true
      }
    );

  if (readError) {
    return res.status(500).json({
      error: "Could not save read receipt."
    });
  }

  res.json({ ok: true });
});

app.get("/api/inbox/messages/:id/reads", needDb, auth, admin, async (req, res) => {
  const { data: message, error } = await db
    .from("inbox_messages")
    .select("*")
    .eq("id", req.params.id)
    .maybeSingle();

  if (error || !message) {
    return res.status(404).json({
      error: "Message not found."
    });
  }

  let query = db
    .from("customers")
    .select("id,display_name")
    .eq("active", true)
    .order("display_name");

  if (message.message_type === "personal") {
    query = query.eq("id", message.recipient_customer_id);
  }

  const { data: customers } = await query;

  const { data: reads } = await db
    .from("inbox_reads")
    .select("customer_id,read_at")
    .eq("message_id", message.id);

  const readMap = new Map(
    (reads || []).map(r => [r.customer_id, r.read_at])
  );

  res.json(
    (customers || []).map(c => ({
      customer_id: c.id,
      display_name: c.display_name,
      is_read: readMap.has(c.id),
      read_at: readMap.get(c.id) || null
    }))
  );
});


// ==========================================
// BUSINESS DASHBOARD
// ==========================================

app.get("/api/dashboard", needDb, auth, admin, async (req, res) => {
  const [
    products,
    customers,
    orders,
    expenses,
    suppliers
  ] = await Promise.all([
    db.from("products").select("id,stock_quantity,low_stock_threshold,price,cost_price").eq("active", true),
    db.from("customers").select("id,active").eq("active", true),
    db.from("orders").select("id,total,status,created_at"),
    db.from("expenses").select("amount,expense_date"),
    db.from("suppliers").select("id,active").eq("active", true)
  ]);

  if (
    products.error ||
    customers.error ||
    orders.error ||
    expenses.error ||
    suppliers.error
  ) {
    return res.status(500).json({
      error: "Could not generate dashboard."
    });
  }

  const productRows = products.data || [];
  const orderRows = orders.data || [];
  const expenseRows = expenses.data || [];

  res.json({
    totalProducts: productRows.length,
    totalCustomers: (customers.data || []).length,
    totalSuppliers: (suppliers.data || []).length,
    totalOrders: orderRows.length,
    pendingOrders: orderRows.filter(o => o.status === "pending").length,
    acceptedOrders: orderRows.filter(o => o.status === "accepted").length,
    lowStockProducts: productRows.filter(
      p => Number(p.stock_quantity) <= Number(p.low_stock_threshold)
    ).length,
    totalOrderValue: orderRows.reduce(
      (sum, o) => sum + Number(o.total || 0), 0
    ),
    totalExpenses: expenseRows.reduce(
      (sum, e) => sum + Number(e.amount || 0), 0
    )
  });
});


// ==========================================
// BUSINESS SETTINGS
// ==========================================

app.get("/api/settings", needDb, auth, admin, async (req, res) => {
  const { data, error } = await db
    .from("business_settings")
    .select("*")
    .order("setting_key");

  if (error) {
    return res.status(500).json({
      error: "Could not load settings."
    });
  }

  res.json(data);
});

app.put("/api/settings/:key", needDb, auth, admin, async (req, res) => {
  const key = String(req.params.key || "").trim();

  if (!/^[a-zA-Z0-9_-]{1,80}$/.test(key)) {
    return res.status(400).json({
      error: "Invalid setting key."
    });
  }

  const { data, error } = await db
    .from("business_settings")
    .upsert({
      setting_key: key,
      setting_value: req.body.value,
      updated_at: new Date().toISOString()
    })
    .select()
    .single();

  if (error) {
    return res.status(500).json({
      error: "Could not save setting."
    });
  }

  res.json(data);
});


// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/api/health", (req, res) => {
  res.json({
    app: "JALIYAAN SALES",
    databaseConfigured: supabaseReady
  });
});


// ==========================================
// WHATSAPP NOTIFICATION
// ==========================================

async function notifyAdmin(order) {
  const to = process.env.ADMIN_WHATSAPP_NUMBER;
  const token = process.env.WHATSAPP_TOKEN;
  const phoneId = process.env.WHATSAPP_PHONE_NUMBER_ID;

  if (!to || !token || !phoneId) return;

  const version = process.env.WHATSAPP_API_VERSION || "v23.0";

  await fetch(
    `https://graph.facebook.com/${version}/${phoneId}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to,
        type: "text",
        text: {
          body:
            `JALIYAAN SALES: New order received. ` +
            `Order ID: ${order.id}. Total: ₹${order.total}.`
        }
      })
    }
  );
}


// ==========================================
// SERVER START
// ==========================================

if (require.main === module && !process.env.NETLIFY) {
  const port = process.env.PORT || 3000;

  app.listen(port, () => {
    console.log(
      `JALIYAAN SALES server running on port ${port}`
    );
  });
}

module.exports = app;

// server.js
// Mock API server implementing the provided API documentation.
// Uses json-server for automatic CRUD and adds custom endpoints + JWT auth + file upload handling.

const jsonServer = require("json-server");
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const DB_FILE = path.join(__dirname, "db.json");
const JWT_SECRET = process.env.JWT_SECRET || "very-secret-key";
const JWT_EXPIRES_IN = 3600; // seconds

// create upload dir if not exists
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// multer for multipart handling (photos, logos)
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = Date.now() + "-" + Math.random().toString(36).slice(2, 8);
    cb(null, base + ext);
  },
});
const upload = multer({ storage });


const express = require("express");
const server = express();

const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const adapter = new FileSync(DB_FILE);
const db = low(adapter);

// Helper: create JWT
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// Middleware: require authentication
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authorization header missing or invalid" });
  }
  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // payload example: { id: 123, role: "customer" }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Utility: find resource item or return 404
function getItemOr404(collection, id, res) {
  const item = db.get(collection).find({ id: Number(id) }).value();
  if (!item) {
    res.status(404).json({ error: `${collection.slice(0, -1)} not found` });
    return null;
  }
  return item;
}

// ------------------ API INFO ENDPOINT ------------------

server.get("/", (req, res) => {
  res.json({ message: "Hello from Express on Vercel" });
});

// API info endpoint
server.get("/api", (req, res) => {
  res.json({
    name: "Pidie Ride Mock API",
    version: "1.0.0",
    date: new Date().toISOString()
  });
});

// ------------------ CUSTOM AUTH ENDPOINTS ------------------

// Generic login for customers, drivers, partners, admin
server.post("/api/customers/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.get("customers").find({ email }).value();
  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = signToken({ id: user.id, role: "customer", email: user.email });
  res.json({ token, token_type: "Bearer", expires_in: JWT_EXPIRES_IN });
});

server.post("/api/drivers/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.get("drivers").find({ email }).value();
  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = signToken({ id: user.id, role: "driver", email: user.email });
  res.json({ token, token_type: "Bearer", expires_in: JWT_EXPIRES_IN });
});

server.post("/api/partners/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.get("partners").find({ email }).value();
  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = signToken({ id: user.id, role: "partner", email: user.email });
  res.json({ token, token_type: "Bearer", expires_in: JWT_EXPIRES_IN });
});

server.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.get("admin").find({ email }).value();
  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = signToken({ id: user.id, role: "admin", email: user.email });
  res.json({ token, token_type: "Bearer", expires_in: JWT_EXPIRES_IN });
});

// Refresh token (requires auth)
server.post("/api/customers/refresh-token", requireAuth, (req, res) => {
  // allow refresh for any authenticated role
  const payload = { id: req.user.id, role: req.user.role, email: req.user.email };
  const token = signToken(payload);
  res.json({ token, token_type: "Bearer", expires_in: JWT_EXPIRES_IN });
});
server.post("/api/drivers/refresh-token", requireAuth, (req, res) => {
  const token = signToken({ id: req.user.id, role: req.user.role, email: req.user.email });
  res.json({ token, expires_in: JWT_EXPIRES_IN });
});
server.post("/api/partners/refresh-token", requireAuth, (req, res) => {
  const token = signToken({ id: req.user.id, role: req.user.role, email: req.user.email });
  res.json({ token, expires_in: JWT_EXPIRES_IN });
});
server.post("/api/admin/refresh-token", requireAuth, (req, res) => {
  const token = signToken({ id: req.user.id, role: req.user.role, email: req.user.email });
  res.json({ token, expires_in: JWT_EXPIRES_IN });
});

// Logout endpoints (mock: instruct client to discard token)
server.post("/api/customers/logout", requireAuth, (req, res) => {
  return res.json({ message: "Logout success" });
});
server.post("/api/drivers/logout", requireAuth, (req, res) => {
  return res.json({ message: "Logout success" });
});
server.post("/api/partners/logout", requireAuth, (req, res) => {
  return res.json({ message: "Logout success" });
});
server.post("/api/admin/logout", requireAuth, (req, res) => {
  return res.json({ message: "Logout success" });
});

// ------------------ CUSTOMER PROFILE & PHOTO ------------------

// Get profile
server.get("/api/customers/profile", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const user = db.get("customers").find({ id: req.user.id }).value();
  if (!user) return res.status(404).json({ error: "Customer not found" });
  // omit password
  const { password, ...safe } = user;
  res.json(safe);
});

// Update profile
server.put("/api/customers/profile", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const updates = req.body;
  db.get("customers").find({ id: req.user.id }).assign(updates).write();
  res.json({ message: "Profile updated" });
});

// Change password
server.put("/api/customers/profile/password", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const { oldPassword, newPassword } = req.body;
  const user = db.get("customers").find({ id: req.user.id }).value();
  if (!user || user.password !== oldPassword) return res.status(400).json({ error: "Old password mismatch" });
  db.get("customers").find({ id: req.user.id }).assign({ password: newPassword }).write();
  res.json({ message: "Password changed" });
});

// Upload profile photo (multipart/form-data field 'photo')
server.post("/api/customers/profile/photo", requireAuth, upload.single("photo"), (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  if (!req.file) return res.status(400).json({ error: "No photo uploaded" });
  // In real app you'd upload to cloud => here return local URL
  const photoUrl = `${req.protocol}://${req.get("host")}/` + req.file.filename;
  db.get("customers").find({ id: req.user.id }).assign({ photoUrl }).write();
  res.json({ message: "Photo updated", photoUrl });
});

// ------------------ RESTAURANTS (PUBLIC) ------------------

// List restaurants (partners) for customers - public
server.get("/api/customers/restaurants", (req, res) => {
  const partners = db.get("partners").value() || [];
  // map to limited partner info
  const list = partners.map(p => ({
    id: p.id,
    name: p.name,
    address: p.address,
    rating: p.rating || 0,
    logoUrl: p.logoUrl || null
  }));
  res.json(list);
});

// Restaurant detail (including menu)
server.get("/api/customers/restaurants/:id", (req, res) => {
  const id = Number(req.params.id);
  const partner = getItemOr404("partners", id, res);
  if (!partner) return;
  const menu = db.get("menu").filter({ partnerId: id }).value() || [];
  res.json({ id: partner.id, name: partner.name, address: partner.address, menu });
});

// ------------------ ORDERS (CUSTOMERS) ------------------

// Create order
server.post("/api/customers/orders", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const { partnerId, items, deliveryAddress, paymentMethod } = req.body;
  if (!partnerId || !items || items.length === 0) return res.status(400).json({ error: "Invalid order body" });

  // calculate total by looking up menu prices
  let total = 0;
  const detailedItems = items.map(it => {
    const menuItem = db.get("menu").find({ id: it.menuId, partnerId }).value();
    const price = menuItem ? Number(menuItem.price) : 0;
    const qty = Number(it.quantity) || 0;
    total += price * qty;
    return { menuId: it.menuId, name: menuItem ? menuItem.name : "Unknown", qty, price };
  });

  // create order id
  const orders = db.get("orders");
  const newId = (orders.value() && orders.value().length) ? Math.max(...orders.value().map(o => o.id)) + 1 : 1;

  const order = {
    id: newId,
    customerId: req.user.id,
    partnerId,
    items: detailedItems,
    total,
    status: "pending",
    deliveryAddress,
    paymentMethod,
    createdAt: new Date().toISOString()
  };

  orders.push(order).write();

  // also create a delivery skeleton for drivers (optional)
  const deliveries = db.get("deliveries");
  const deliveryId = (deliveries.value() && deliveries.value().length) ? Math.max(...deliveries.value().map(d => d.id)) + 1 : 1;
  deliveries.push({
    id: deliveryId,
    orderId: order.id,
    status: "ready", // partner will mark ready later; default ready to be picked
    pickupAddress: (db.get("partners").find({ id: partnerId }).value() || {}).address || "",
    dropAddress: deliveryAddress,
    driverId: null
  }).write();

  res.json({ id: order.id, customerId: order.customerId, partnerId: order.partnerId, total: order.total, status: order.status, createdAt: order.createdAt });
});

// List customer's orders
server.get("/api/customers/orders", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const list = db.get("orders").filter({ customerId: req.user.id }).value() || [];
  // map to brief response
  const out = list.map(o => {
    const partner = db.get("partners").find({ id: o.partnerId }).value() || {};
    return { id: o.id, partnerName: partner.name || "Partner", total: o.total, status: o.status, createdAt: o.createdAt };
  });
  res.json(out);
});

// Order detail
server.get("/api/customers/orders/:id", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const order = getItemOr404("orders", id, res);
  if (!order) return;
  if (order.customerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  res.json(order);
});

// Cancel order
server.post("/api/customers/orders/:id/cancel", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const order = getItemOr404("orders", id, res);
  if (!order) return;
  if (order.customerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.get("orders").find({ id }).assign({ status: "cancelled" }).write();
  res.json({ message: "Order cancelled" });
});

// ------------------ RIDES (CUSTOMERS) ------------------

// Create ride
server.post("/api/customers/rides", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const { pickupLocation, dropLocation, vehicleType } = req.body;
  const rides = db.get("rides");
  const newId = (rides.value() && rides.value().length) ? Math.max(...rides.value().map(r => r.id)) + 1 : 1;

  const ride = {
    id: newId,
    customerId: req.user.id,
    pickupLocation,
    dropLocation,
    vehicleType,
    status: "pending",
    createdAt: new Date().toISOString(),
    driverId: null
  };

  rides.push(ride).write();

  res.json({
    id: ride.id,
    customerId: ride.customerId,
    pickupLocation: { address: pickupLocation.address },
    dropLocation: { address: dropLocation.address },
    status: ride.status,
    createdAt: ride.createdAt,
  });
});

// List rides for customer
server.get("/api/customers/rides", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const list = db.get("rides").filter({ customerId: req.user.id }).value() || [];
  const out = list.map(r => ({ id: r.id, status: r.status, driverId: r.driverId, pickupAddress: r.pickupLocation.address, dropAddress: r.dropLocation.address }));
  res.json(out);
});

// Ride detail
server.get("/api/customers/rides/:id", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const ride = getItemOr404("rides", id, res);
  if (!ride) return;
  if (ride.customerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  // if driver assigned, include driver info
  const driver = ride.driverId ? db.get("drivers").find({ id: ride.driverId }).value() : null;
  res.json({
    id: ride.id,
    status: ride.status,
    driver: driver ? { id: driver.id, name: driver.name } : null,
    pickup: { address: ride.pickupLocation.address },
    drop: { address: ride.dropLocation.address }
  });
});

// Cancel ride
server.post("/api/customers/rides/:id/cancel", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const ride = getItemOr404("rides", id, res);
  if (!ride) return;
  if (ride.customerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.get("rides").find({ id }).assign({ status: "cancelled" }).write();
  res.json({ message: "Ride cancelled" });
});

// ------------------ NOTIFICATIONS ------------------

// List notifications for customer
server.get("/api/customers/notifications", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const list = db.get("notifications").filter({ userId: req.user.id }).value() || [];
  res.json(list);
});

// Mark notification read
server.post("/api/customers/notifications/:id/read", requireAuth, (req, res) => {
  if (req.user.role !== "customer") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const notif = getItemOr404("notifications", id, res);
  if (!notif) return;
  if (notif.userId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.get("notifications").find({ id }).assign({ read: true }).write();
  res.json({ message: "Notification marked as read" });
});

// ------------------ DRIVER PROFILE & STATUS ------------------

server.get("/api/drivers/profile", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const driver = db.get("drivers").find({ id: req.user.id }).value();
  if (!driver) return res.status(404).json({ error: "Driver not found" });
  const { password, ...safe } = driver;
  res.json(safe);
});

server.put("/api/drivers/profile", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  db.get("drivers").find({ id: req.user.id }).assign(req.body).write();
  res.json({ message: "Profile updated" });
});

server.put("/api/drivers/profile/password", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const { oldPassword, newPassword } = req.body;
  const d = db.get("drivers").find({ id: req.user.id }).value();
  if (!d || d.password !== oldPassword) return res.status(400).json({ error: "Old password mismatch" });
  db.get("drivers").find({ id: req.user.id }).assign({ password: newPassword }).write();
  res.json({ message: "Password changed" });
});

server.post("/api/drivers/profile/status", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const { available } = req.body;
  db.get("drivers").find({ id: req.user.id }).assign({ status: available ? "available" : "unavailable" }).write();
  res.json({ message: "Status updated", available: !!available });
});

// ------------------ DELIVERIES (DRIVER) ------------------

// List deliveries assigned or available
server.get("/api/drivers/deliveries", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  // show deliveries that are 'ready' or assigned to this driver
  const list = db.get("deliveries").filter(d => d.status === "ready" || d.driverId === req.user.id).value() || [];
  res.json(list);
});

// Delivery detail
server.get("/api/drivers/deliveries/:id", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const d = getItemOr404("deliveries", id, res);
  if (!d) return;
  res.json(d);
});

// Accept delivery
server.post("/api/drivers/deliveries/:id/accept", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const d = getItemOr404("deliveries", id, res);
  if (!d) return;
  db.get("deliveries").find({ id }).assign({ status: "accepted", driverId: req.user.id }).write();
  res.json({ message: "Delivery accepted", deliveryId: id });
});

// Reject delivery
server.post("/api/drivers/deliveries/:id/reject", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const { reason } = req.body || {};
  const d = getItemOr404("deliveries", id, res);
  if (!d) return;
  db.get("deliveries").find({ id }).assign({ status: "rejected", rejectReason: reason || null }).write();
  res.json({ message: "Delivery rejected" });
});

// Start delivery
server.post("/api/drivers/deliveries/:id/start", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  db.get("deliveries").find({ id }).assign({ status: "ongoing" }).write();
  res.json({ message: "Delivery started" });
});

// Complete delivery
server.post("/api/drivers/deliveries/:id/complete", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const { collectedAmount } = req.body;
  db.get("deliveries").find({ id }).assign({ status: "completed", collectedAmount: Number(collectedAmount) || 0 }).write();
  res.json({ message: "Delivery completed", collectedAmount: Number(collectedAmount) || 0 });
});

// ------------------ RIDES (DRIVER) ------------------

// List available ride requests for driver
server.get("/api/drivers/rides", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  // show rides with status pending (not assigned)
  const list = db.get("rides").filter({ status: "pending" }).value() || [];
  res.json(list);
});

// Accept ride
server.post("/api/drivers/rides/:id/accept", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const r = getItemOr404("rides", id, res);
  if (!r) return;
  db.get("rides").find({ id }).assign({ status: "ongoing", driverId: req.user.id }).write();
  res.json({ message: "Ride accepted" });
});

// Reject ride
server.post("/api/drivers/rides/:id/reject", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const { reason } = req.body || {};
  db.get("rides").find({ id }).assign({ status: "rejected", rejectReason: reason || null }).write();
  res.json({ message: "Ride rejected" });
});

server.post("/api/drivers/rides/:id/start", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  db.get("rides").find({ id }).assign({ status: "ongoing" }).write();
  res.json({ message: "Ride started" });
});

server.post("/api/drivers/rides/:id/complete", requireAuth, (req, res) => {
  if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.id);
  const { fareCollected } = req.body;
  db.get("rides").find({ id }).assign({ status: "completed", fareCollected: Number(fareCollected) || 0 }).write();
  res.json({ message: "Ride completed", fareCollected: Number(fareCollected) || 0 });
});

// ------------------ PARTNER (RESTAURANT) ENDPOINTS ------------------

// Register partner - handled by json-server default POST /partners
// Partner profile
server.get("/api/partners/profile", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const p = db.get("partners").find({ id: req.user.id }).value();
  if (!p) return res.status(404).json({ error: "Partner not found" });
  const { password, ...safe } = p;
  res.json(safe);
});

server.put("/api/partners/profile", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  db.get("partners").find({ id: req.user.id }).assign(req.body).write();
  res.json({ message: "Profile updated" });
});

server.put("/api/partners/profile/password", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const { oldPassword, newPassword } = req.body;
  const p = db.get("partners").find({ id: req.user.id }).value();
  if (!p || p.password !== oldPassword) return res.status(400).json({ error: "Old password mismatch" });
  db.get("partners").find({ id: req.user.id }).assign({ password: newPassword }).write();
  res.json({ message: "Password changed" });
});

// Upload logo (field 'logo')
server.post("/api/partners/profile/logo", requireAuth, upload.single("logo"), (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  if (!req.file) return res.status(400).json({ error: "No logo uploaded" });
  const logoUrl = `${req.protocol}://${req.get("host")}/` + req.file.filename;
  db.get("partners").find({ id: req.user.id }).assign({ logoUrl }).write();
  res.json({ message: "Logo updated", logoUrl });
});

// Partner menu endpoints - require partner auth
server.get("/api/partners/menu", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const menu = db.get("menu").filter({ partnerId: req.user.id }).value() || [];
  res.json(menu);
});

// Add menu item
server.post("/api/partners/menu", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const { name, price, description, category } = req.body;
  const menu = db.get("menu");
  const newId = (menu.value() && menu.value().length) ? Math.max(...menu.value().map(m => m.id)) + 1 : 1;
  const item = { id: newId, name, price: Number(price) || 0, description: description || "", category: category || "", partnerId: req.user.id };
  menu.push(item).write();
  res.json({ id: item.id, name: item.name, price: item.price, partnerId: item.partnerId });
});

// Update menu
server.put("/api/partners/menu/:menuId", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const menuId = Number(req.params.menuId);
  const menuItem = db.get("menu").find({ id: menuId, partnerId: req.user.id }).value();
  if (!menuItem) return res.status(404).json({ error: "Menu not found" });
  db.get("menu").find({ id: menuId }).assign(req.body).write();
  res.json({ message: "Menu updated" });
});

// Delete menu
server.delete("/api/partners/menu/:menuId", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const menuId = Number(req.params.menuId);
  const menuItem = db.get("menu").find({ id: menuId, partnerId: req.user.id }).value();
  if (!menuItem) return res.status(404).json({ error: "Menu not found" });
  db.get("menu").remove({ id: menuId }).write();
  res.json({ message: "Menu deleted" });
});

// Partner incoming orders
server.get("/api/partners/orders/incoming", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const orders = db.get("orders").filter({ partnerId: req.user.id }).value() || [];
  res.json(orders.map(o => ({ id: o.id, customerId: o.customerId, total: o.total, status: o.status })));
});

// Partner order detail
server.get("/api/partners/orders/:orderId", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.orderId);
  const order = getItemOr404("orders", id, res);
  if (!order) return;
  if (order.partnerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  res.json(order);
});

// Accept order
server.post("/api/partners/orders/:orderId/accept", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.orderId);
  const order = getItemOr404("orders", id, res);
  if (!order) return;
  if (order.partnerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.get("orders").find({ id }).assign({ status: "accepted" }).write();
  res.json({ message: "Order accepted" });
});

// Reject order
server.post("/api/partners/orders/:orderId/reject", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.orderId);
  const { reason } = req.body || {};
  const order = getItemOr404("orders", id, res);
  if (!order) return;
  if (order.partnerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.get("orders").find({ id }).assign({ status: "rejected", rejectReason: reason || null }).write();
  res.json({ message: "Order rejected" });
});

// Mark order ready (for driver pickup)
server.post("/api/partners/orders/:orderId/ready", requireAuth, (req, res) => {
  if (req.user.role !== "partner") return res.status(403).json({ error: "Forbidden" });
  const id = Number(req.params.orderId);
  const order = getItemOr404("orders", id, res);
  if (!order) return;
  if (order.partnerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.get("orders").find({ id }).assign({ status: "ready" }).write();
  res.json({ message: "Order ready" });
});

// ------------------ ADMIN ENDPOINTS ------------------

server.post("/api/admin/register", (req, res) => {
  // allow register via json-server or custom
  // for convenience we'll use json-server default but mask password in response
  const admin = req.body;
  if (!admin.email || !admin.password) return res.status(400).json({ error: "Missing fields" });
  // assign id
  const admins = db.get("admin");
  const newId = (admins.value() && admins.value().length) ? Math.max(...admins.value().map(a => a.id)) + 1 : 1;
  admin.id = newId;
  admins.push(admin).write();
  const { password, ...safe } = admin;
  res.json(safe);
});

// Admin login handled earlier

// Dashboard stats
server.get("/api/admin/dashboard", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  const customers = db.get("customers").value().length;
  const drivers = db.get("drivers").value().length;
  const partners = db.get("partners").value().length;
  const orders = db.get("orders").value().length;
  const rides = db.get("rides").value().length;
  res.json({ customers, drivers, partners, orders, rides });
});

// Admin list endpoints (use json-server's list or custom)
server.get("/api/admin/customers", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  const list = db.get("customers").map(c => ({ id: c.id, name: c.name, email: c.email })).value();
  res.json(list);
});
server.get("/api/admin/drivers", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  res.json(db.get("drivers").map(d => ({ id: d.id, name: d.name, vehicle: d.vehicle })).value());
});
server.get("/api/admin/partners", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  res.json(db.get("partners").map(p => ({ id: p.id, name: p.name, address: p.address })).value());
});
server.get("/api/admin/orders", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  res.json(db.get("orders").value());
});
server.get("/api/admin/rides", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  res.json(db.get("rides").value());
});

// ------------------ SIMPLE PUBLIC / STATUS ------------------
server.get("/api/status", (req, res) => {
  res.json({ status: "OK", time: new Date().toISOString() });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ Mock API server running at http://localhost:${PORT}/api`);
  console.log(`Upload folder: ${UPLOAD_DIR}`);
});

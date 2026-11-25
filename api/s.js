// DK HBR POS - server (Vercel serverless function at /api/s)
// Storage: Supabase table public.kv (k text primary key, v jsonb). No npm packages needed.
// Env: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, ADMIN_SETUP_CODE, SESSION_SECRET (optional)
const crypto = require("crypto");

/* ---------- small helpers ---------- */
class HttpErr extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (m) => new HttpErr(400, m);          // 400 never logs the user out
const E = (c, m) => new HttpErr(c, m);

const uid = () => crypto.randomBytes(6).toString("hex");
const now = () => Date.now();
const str = (v, n = 200) => String(v == null ? "" : v).trim().slice(0, n);
const digits = (v) => String(v || "").replace(/\D/g, "");
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const lc = (v) => str(v, 200).toLowerCase();
const sha = (v) => crypto.createHash("sha256").update(String(v)).digest("hex").slice(0, 24);
const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

/* ---------- Supabase REST ---------- */
const ENV_URL = () => process.env.SUPABASE_URL || process.env.SUPABASE_URL_SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL_SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const ENV_KEY = () => process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_URL_SUPABASE_SERVICE_ROLE_KEY || "";
function cfg() {
  const url = ENV_URL().replace(/\/+$/, "");
  const key = ENV_KEY();
  if (!url || !key) throw E(500, "Server not set up: add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in Vercel, then redeploy.");
  return { url: url + "/rest/v1/kv", key };
}
async function sb(method, query, body, prefer) {
  const { url, key } = cfg();
  const h = { apikey: key, Authorization: "Bearer " + key, "Content-Type": "application/json" };
  if (prefer) h.Prefer = prefer;
  const r = await fetch(url + query, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const txt = await r.text();
  if (!r.ok) { console.error("Supabase", r.status, txt); throw E(500, "Database error. Check that supabase.sql was run and the Supabase keys are correct."); }
  return txt ? JSON.parse(txt) : [];
}
const enc = encodeURIComponent;
async function get(k) { const r = await sb("GET", `?k=eq.${enc(k)}&select=v`); return r.length ? r[0].v : null; }
async function put(k, v) { await sb("POST", "?on_conflict=k", { k, v, updated_at: new Date().toISOString() }, "resolution=merge-duplicates"); return v; }
async function del(k) { await sb("DELETE", `?k=eq.${enc(k)}`); }
async function addNew(k, v) { // true only if the key did not exist
  const r = await sb("POST", "?on_conflict=k", { k, v }, "resolution=ignore-duplicates,return=representation");
  return r.length > 0;
}
async function list(prefix, limit = 1000) {
  const r = await sb("GET", `?k=like.${enc(prefix + "*")}&select=k,v&order=updated_at.desc&limit=${limit}`);
  return r.map((x) => x.v);
}

/* ---------- passwords, PINs, tokens ---------- */
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return "s1$" + salt + "$" + crypto.scryptSync(String(pw), salt, 32).toString("hex");
}
function checkPw(pw, stored) {
  try {
    const [v, salt, h] = String(stored).split("$");
    if (v !== "s1") return false;
    return same(crypto.scryptSync(String(pw), salt, 32).toString("hex"), h);
  } catch (e) { return false; }
}
function secret() {
  return process.env.SESSION_SECRET ||
    crypto.createHash("sha256").update(ENV_KEY() + "|" + (process.env.ADMIN_SETUP_CODE || "")).digest("hex");
}
const b64 = (s) => Buffer.from(s).toString("base64url");
function sign(p) {
  const body = b64(JSON.stringify(Object.assign({ exp: now() + 12 * 3600 * 1000 }, p)));
  return body + "." + crypto.createHmac("sha256", secret()).update(body).digest("base64url");
}
function unsign(t) {
  if (!t || typeof t !== "string" || !t.includes(".")) return null;
  const [body, sig] = t.split(".");
  const ok = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  if (!same(sig, ok)) return null;
  try { const p = JSON.parse(Buffer.from(body, "base64url").toString()); return p.exp > now() ? p : null; } catch (e) { return null; }
}

/* ---------- throttling (stored in kv) ---------- */
async function lockCheck(key, max, win) {
  const r = await get("rl:" + key);
  if (r && now() - r.ts < win && r.n >= max) throw E(429, "Too many attempts. Please wait a few minutes and try again.");
}
async function lockHit(key, win) {
  const r = await get("rl:" + key);
  await put("rl:" + key, r && now() - r.ts < win ? { n: r.n + 1, ts: r.ts } : { n: 1, ts: now() });
}
const lockClear = (key) => del("rl:" + key).catch(() => {});

/* ---------- constants ---------- */
const ROLES = ["waiter", "cashier", "supervisor", "manager", "owner"];
const SEN = ["owner", "manager", "supervisor"];
const STF = ["owner", "manager"];
const DEPTS = ["Restaurant", "Bar", "Spa", "Hotel"];
const PAYS = ["Cash", "M-Pesa", "Card", "Room"];
const BSTAT = ["Requested", "Confirmed", "Arrived", "Done", "Cancelled"];
const DEFAULT_TAG = "Welcome. Book your room, table or treatment online and we will confirm with you.";

/* ---------- tenants ---------- */
const tKey = (tid, coll, id) => `t:${tid}:${coll}` + (id ? ":" + id : "");
async function tenantBySlug(slug) {
  const id = await get("p:slug:" + lc(slug).replace(/[^a-z0-9]/g, ""));
  return id ? get("p:tenant:" + id) : null;
}
async function allTenants() { return list("p:tenant:"); }
async function makeSlug(name) {
  let base = lc(name).replace(/[^a-z0-9]/g, "").slice(0, 10) || "hotel";
  let slug = base, i = 1;
  while (await get("p:slug:" + slug)) { i++; slug = base + i; }
  return slug;
}
async function emailTaken(email) {
  const admin = await get("p:admin");
  if (admin && admin.email === email) return true;
  if ((await allTenants()).some((t) => t.email === email)) return true;
  if ((await list("p:req:")).some((r) => r.status === "pending" && r.email === email)) return true;
  return false;
}
function cleanSignup(b) {
  const x = {
    name: str(b.name, 80), owner: str(b.owner, 80), email: lc(b.email),
    phone: str(b.phone, 30), loc: str(b.loc, 80), pw: String(b.pw || ""),
  };
  if (!x.name || !x.owner) throw bad("Enter the hotel name and the owner name.");
  if (!emailOk(x.email)) throw bad("Enter a valid email address.");
  if (digits(x.phone).length < 9) throw bad("Enter a valid phone number.");
  if (x.pw.length < 8) throw bad("Password must be at least 8 characters.");
  return x;
}
const LIFE = 4102444800000; // "paid forever" marker for one-time packages
function cleanPkg(b) {
  const plan = str(b.plan, 40) || "Standard";
  const fee = b.fee === undefined || b.fee === "" ? 0 : Number(b.fee);
  if (!isFinite(fee) || fee < 0 || fee > 1e9) throw bad("Enter a valid package fee.");
  const period = ["month", "year", "once"].includes(b.period) ? b.period : "month";
  return { plan, fee: Math.round(fee * 100) / 100, period };
}
async function createTenant(x, ownerHash, pk) {
  const id = uid(), slug = await makeSlug(x.name);
  const t = { id, slug, name: x.name, owner: x.owner, email: x.email, phone: x.phone, loc: x.loc, status: "active", ownerHash, ts: now(),
    plan: pk.plan, fee: pk.fee, period: pk.period, paidUntil: 0 };
  await put("p:tenant:" + id, t);
  await put("p:slug:" + slug, id);
  await put(tKey(id, "cfg"), { name: x.name, phone: x.phone, addr: x.loc, tag: DEFAULT_TAG });
  return t;
}

/* ---------- session ---------- */
async function session(b) {
  const p = unsign(b.t);
  if (!p) throw E(401, "Please sign in again.");
  if (p.r === "platform") {
    const a = await get("p:admin");
    if (!a || a.email !== p.e) throw E(401, "Please sign in again.");
    return { role: "platform", name: a.name };
  }
  const t = await get("p:tenant:" + p.tid);
  if (!t) throw E(401, "Please sign in again.");
  if (t.status !== "active") throw E(403, "This account is suspended. Contact DK Global Tech.");
  if (p.r === "owner") return { role: "owner", name: t.owner, tid: t.id, t };
  const s = await get(tKey(t.id, "staff", p.sid));
  if (!s) throw E(401, "Your access was removed.");
  return { role: s.role, name: s.name, tid: t.id, sid: s.id, t };
}
const need = (me, roles) => { if (!roles.includes(me.role)) throw bad("Your role cannot do this."); };

/* ---------- actions: public ---------- */
async function aStatus() { return { setup: !(await get("p:admin")) }; }

async function aSetup(b, ip) {
  if (await get("p:admin")) throw bad("Setup is already done. Sign in as Owner or admin.");
  const want = process.env.ADMIN_SETUP_CODE || "";
  if (!want) throw E(500, "Server not set up: add ADMIN_SETUP_CODE in Vercel, then redeploy.");
  await lockCheck("setup:" + sha(ip), 8, 15 * 60e3);
  if (!same(String(b.code || ""), want)) { await lockHit("setup:" + sha(ip), 15 * 60e3); throw bad("Wrong setup code."); }
  const name = str(b.name, 80), email = lc(b.email), pw = String(b.pw || "");
  if (!name) throw bad("Enter your name.");
  if (!emailOk(email)) throw bad("Enter a valid email address.");
  if (pw.length < 8) throw bad("Password must be at least 8 characters.");
  if (!(await addNew("p:admin", { name, email, hash: hashPw(pw), ts: now() }))) throw bad("Setup is already done.");
  return { t: sign({ r: "platform", e: email }), me: { name, role: "platform" } };
}

async function aLogin(b, ip) {
  if (b.email !== undefined) {
    const email = lc(b.email), pw = String(b.pw || ""), lk = "em:" + sha(email + ip);
    await lockCheck(lk, 8, 15 * 60e3);
    const fail = async () => { await lockHit(lk, 15 * 60e3); throw E(401, "Wrong email or password."); };
    if (!email || !pw) throw bad("Enter your email and password.");
    const admin = await get("p:admin");
    if (admin && admin.email === email) {
      if (!checkPw(pw, admin.hash)) return fail();
      await lockClear(lk);
      return { t: sign({ r: "platform", e: email }), me: { name: admin.name, role: "platform" } };
    }
    const t = (await allTenants()).find((x) => x.email === email);
    if (t) {
      if (!checkPw(pw, t.ownerHash)) return fail();
      if (t.status !== "active") throw E(401, "This account is suspended. Contact DK Global Tech.");
      await lockClear(lk);
      return { t: sign({ r: "owner", tid: t.id }), me: { name: t.owner, role: "owner" } };
    }
    const rq = (await list("p:req:")).find((x) => x.email === email && x.status !== "approved");
    if (rq && checkPw(pw, rq.hash))
      throw E(401, rq.status === "pending" ? "Your request is still being reviewed. We will approve it soon." : "This request was not approved. Contact DK Global Tech.");
    return fail();
  }
  const slug = lc(b.h), name = lc(b.name), pin = String(b.pin || "");
  if (!slug || !name || !pin) throw bad("Enter the hotel code, your name and your PIN.");
  const lk = "st:" + sha(slug + name + ip);
  await lockCheck(lk, 8, 15 * 60e3);
  const t = await tenantBySlug(slug);
  const staff = t ? (await list(tKey(t.id, "staff") + ":")).find((s) => lc(s.name) === name) : null;
  if (!t || !staff || !checkPw(pin, staff.pinHash)) { await lockHit(lk, 15 * 60e3); throw E(401, "Wrong hotel code, name or PIN."); }
  if (t.status !== "active") throw E(401, "This account is suspended. Contact the hotel owner.");
  await lockClear(lk);
  return { t: sign({ r: "staff", tid: t.id, sid: staff.id }), me: { name: staff.name, role: staff.role } };
}

async function aSignup(b, ip) {
  await lockCheck("su:" + sha(ip), 6, 3600e3);
  const x = cleanSignup(b);
  if (await emailTaken(x.email)) throw bad("That email is already registered or waiting for approval.");
  const id = uid();
  await put("p:req:" + id, { id, name: x.name, owner: x.owner, email: x.email, phone: x.phone, loc: x.loc, hash: hashPw(x.pw), status: "pending", ts: now() });
  await lockHit("su:" + sha(ip), 3600e3);
  return { ok: true };
}

async function aPub(b) {
  const t = await tenantBySlug(b.h);
  if (!t || t.status !== "active") throw E(404, "Hotel not found. Check the link.");
  const c = (await get(tKey(t.id, "cfg"))) || {};
  return { name: c.name || t.name, tag: c.tag || DEFAULT_TAG, phone: c.phone || t.phone || "", addr: c.addr || t.loc || "" };
}

async function aBook(b, ip) {
  const t = await tenantBySlug(b.h);
  if (!t || t.status !== "active") throw E(404, "Hotel not found. Check the link.");
  await lockCheck("bk:" + sha(ip), 12, 3600e3);
  const name = str(b.name, 80), phone = str(b.phone, 30), service = str(b.service, 60);
  const date = str(b.date, 10), time = str(b.time, 5) || "12:00", guests = Math.round(+b.guests) || 1;
  if (!name) throw bad("Enter your name.");
  if (digits(phone).length < 9) throw bad("Enter a valid phone number.");
  if (!service) throw bad("Choose a service.");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw bad("Choose a date.");
  if (!/^\d{2}:\d{2}$/.test(time)) throw bad("Choose a time.");
  if (guests < 1 || guests > 500) throw bad("Enter the number of guests.");
  const email = lc(b.email);
  if (email && !emailOk(email)) throw bad("That email address looks wrong.");
  const id = uid(), ref = "BK" + crypto.randomBytes(3).toString("hex").toUpperCase();
  await put(tKey(t.id, "bookings", id), { id, ref, service, date, time, guests, name, phone, email, notes: str(b.notes, 500), status: "Requested", ts: now() });
  await lockHit("bk:" + sha(ip), 3600e3);
  return { ref };
}

/* ---------- actions: platform admin ---------- */
async function pReq(id) {
  const r = id ? await get("p:req:" + id) : null;
  if (!r) throw bad("Request not found.");
  return r;
}
async function aPApprove(b) {
  const r = await pReq(b.id);
  if (r.status !== "pending") throw bad("This request was already handled.");
  const pk = cleanPkg(b);
  const t = await createTenant(r, r.hash, pk);
  await put("p:req:" + r.id, Object.assign({}, r, { status: "approved", hash: "", ts2: now() }));
  return { ok: true, slug: t.slug, id: t.id };
}
async function aPReject(b) {
  const r = await pReq(b.id);
  if (r.status !== "pending") throw bad("This request was already handled.");
  await put("p:req:" + r.id, Object.assign({}, r, { status: "rejected", ts2: now() }));
  return { ok: true };
}
async function aPCreate(b) {
  const x = cleanSignup(b), pk = cleanPkg(b);
  if (await emailTaken(x.email)) throw bad("That email is already registered.");
  const t = await createTenant(x, hashPw(x.pw), pk);
  return { ok: true, slug: t.slug, id: t.id };
}
async function aPStatus(b) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null;
  if (!t) throw bad("Client not found.");
  if (!["active", "suspended"].includes(b.status)) throw bad("Invalid status.");
  t.status = b.status; await put("p:tenant:" + t.id, t);
  return { ok: true };
}
async function aPPlan(b) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null;
  if (!t) throw bad("Client not found.");
  Object.assign(t, cleanPkg(b));
  if (b.paidUntil !== undefined) {
    const d = str(b.paidUntil, 10);
    if (!d) { if (!(t.paidUntil >= LIFE && t.period === "once")) t.paidUntil = 0; }
    else {
      const ms = /^\d{4}-\d{2}-\d{2}$/.test(d) ? new Date(d + "T23:59:59+03:00").getTime() : NaN;
      if (!isFinite(ms)) throw bad("Check the paid-until date.");
      t.paidUntil = ms;
    }
  }
  await put("p:tenant:" + t.id, t);
  return { ok: true };
}
async function aPPaid(b) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null;
  if (!t) throw bad("Client not found.");
  if (!t.plan) throw bad("Set the package first.");
  if (t.period === "once") t.paidUntil = LIFE;
  else {
    const base = t.paidUntil >= LIFE ? now() : Math.max(now(), t.paidUntil || 0);
    const d = new Date(base); d.setMonth(d.getMonth() + (t.period === "year" ? 12 : 1));
    t.paidUntil = d.getTime();
  }
  t.lastPaid = now();
  await put("p:tenant:" + t.id, t);
  return { ok: true };
}
async function aPSettings(b) {
  const site = str(b.site, 200).replace(/\/+$/, "");
  if (site && !/^https?:\/\//i.test(site)) throw bad("The site address must start with https://");
  await put("p:settings", { pay: str(b.pay, 600), contact: str(b.contact, 120), site });
  return { ok: true };
}
async function aPReset(b) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null;
  if (!t) throw bad("Client not found.");
  if (String(b.pw || "").length < 8) throw bad("Password must be at least 8 characters.");
  t.ownerHash = hashPw(b.pw); await put("p:tenant:" + t.id, t);
  return { ok: true };
}

/* ---------- actions: hotel ---------- */
async function aSync(b, me) {
  if (me.role === "platform") {
    const reqs = (await list("p:req:")).filter((r) => r.status === "pending" || r.status === "rejected")
      .map((r) => ({ id: r.id, name: r.name, owner: r.owner, email: r.email, phone: r.phone, loc: r.loc, status: r.status, ts: r.ts }))
      .sort((a, c) => c.ts - a.ts);
    const tenants = (await allTenants()).map((t) => ({ id: t.id, slug: t.slug, name: t.name, owner: t.owner, email: t.email, phone: t.phone, status: t.status, ts: t.ts,
      plan: t.plan || "", fee: t.fee || 0, period: t.period || "month", paidUntil: t.paidUntil || 0 }))
      .sort((a, c) => c.ts - a.ts);
    return { me: { name: me.name, role: "platform" }, reqs, tenants, pset: (await get("p:settings")) || {} };
  }
  const tid = me.tid, sen = SEN.includes(me.role);
  const [c, menu, orders, bookings, stock, staff] = await Promise.all([
    get(tKey(tid, "cfg")), list(tKey(tid, "menu") + ":"), list(tKey(tid, "orders") + ":", 300),
    list(tKey(tid, "bookings") + ":", 300), sen ? list(tKey(tid, "stock") + ":") : [], STF.includes(me.role) ? list(tKey(tid, "staff") + ":") : [],
  ]);
  const byName = (a, z) => String(a.name).localeCompare(String(z.name));
  let pkg;
  if (STF.includes(me.role)) {
    const ps = (await get("p:settings")) || {};
    pkg = { plan: me.t.plan || "", fee: me.t.fee || 0, period: me.t.period || "month", paidUntil: me.t.paidUntil || 0, pay: ps.pay || "" };
  }
  return {
    me: { name: me.name, role: me.role }, slug: me.t.slug, pkg,
    cfg: { name: (c && c.name) || me.t.name, phone: (c && c.phone) || "", addr: (c && c.addr) || "", tag: (c && c.tag) || "" },
    menu: menu.sort(byName),
    orders: orders.sort((a, z) => z.ts - a.ts),
    bookings,
    stock: stock.sort(byName),
    staff: staff.map((s) => ({ id: s.id, name: s.name, role: s.role })).sort(byName),
  };
}

async function aCfg(b, me) {
  need(me, STF);
  const name = str(b.name, 80);
  if (!name) throw bad("Enter the hotel name.");
  await put(tKey(me.tid, "cfg"), { name, phone: str(b.phone, 30), addr: str(b.addr, 120), tag: str(b.tag, 200) });
  return { ok: true };
}

async function aAdd(b, me) {
  const c = b.c, it = b.item || {};
  if (c === "stock") {
    need(me, SEN);
    const name = str(it.name, 80); if (!name) throw bad("Enter an item name.");
    const o = { id: uid(), name, qty: +it.qty || 0, unit: str(it.unit, 20) || "unit", min: +it.min || 0 };
    await put(tKey(me.tid, "stock", o.id), o); return { ok: true, id: o.id };
  }
  if (c === "menu") {
    need(me, SEN);
    const name = str(it.name, 80), price = +it.price;
    if (!name || !(price > 0)) throw bad("Enter a name and a price.");
    if (!DEPTS.includes(it.dept)) throw bad("Choose a section.");
    let sku = str(it.sku, 40);
    if (sku && !(await get(tKey(me.tid, "stock", sku)))) sku = "";
    const o = { id: uid(), name, price, dept: it.dept, sku };
    await put(tKey(me.tid, "menu", o.id), o); return { ok: true, id: o.id };
  }
  if (c === "staff") {
    need(me, STF);
    const name = str(it.name, 60), pin = String(it.pin || "").trim(), role = it.role;
    if (!name) throw bad("Enter the staff name.");
    if (!/^\d{4,8}$/.test(pin)) throw bad("PIN must be 4 to 8 digits.");
    if (!ROLES.includes(role)) throw bad("Choose a role.");
    if (role === "owner" && me.role !== "owner") throw bad("Only the owner can add another owner.");
    if ((await list(tKey(me.tid, "staff") + ":")).some((s) => lc(s.name) === lc(name))) throw bad("Someone with that name already exists.");
    const o = { id: uid(), name, role, pinHash: hashPw(pin) };
    await put(tKey(me.tid, "staff", o.id), o); return { ok: true, id: o.id };
  }
  throw bad("Unknown item type.");
}

async function aUpd(b, me) {
  const c = b.c, id = str(b.id, 40), patch = b.patch || {};
  if (c === "bookings") {
    const o = await get(tKey(me.tid, "bookings", id)); if (!o) throw bad("Booking not found.");
    if (!BSTAT.includes(patch.status)) throw bad("Invalid status.");
    o.status = patch.status; await put(tKey(me.tid, "bookings", id), o); return { ok: true };
  }
  need(me, SEN);
  if (c === "stock") {
    const o = await get(tKey(me.tid, "stock", id)); if (!o) throw bad("Stock item not found.");
    const d = +patch.delta; if (!d || !isFinite(d)) throw bad("Enter a number, like 24 or -3.");
    o.qty = Math.round((o.qty + d) * 1000) / 1000; await put(tKey(me.tid, "stock", id), o); return { ok: true };
  }
  if (c === "menu") {
    const o = await get(tKey(me.tid, "menu", id)); if (!o) throw bad("Menu item not found.");
    if (patch.name !== undefined) o.name = str(patch.name, 80) || o.name;
    if (patch.price !== undefined && +patch.price > 0) o.price = +patch.price;
    if (patch.dept !== undefined && DEPTS.includes(patch.dept)) o.dept = patch.dept;
    await put(tKey(me.tid, "menu", id), o); return { ok: true };
  }
  throw bad("Unknown item type.");
}

async function aDel(b, me) {
  const c = b.c, id = str(b.id, 40);
  if (!["stock", "menu", "staff"].includes(c)) throw bad("Unknown item type.");
  need(me, c === "staff" ? STF : SEN);
  if (c === "staff") {
    if (id === me.sid) throw bad("You cannot remove yourself.");
    const s = await get(tKey(me.tid, "staff", id));
    if (s && s.role === "owner" && me.role !== "owner") throw bad("Only the owner can remove an owner.");
  }
  await del(tKey(me.tid, c, id));
  return { ok: true };
}

/* stock helper: apply { stockId: delta } */
async function moveStock(tid, deltas) {
  for (const [sid, d] of Object.entries(deltas)) {
    if (!d) continue;
    const s = await get(tKey(tid, "stock", sid)); if (!s) continue;
    s.qty = Math.round((s.qty + d) * 1000) / 1000; await put(tKey(tid, "stock", sid), s);
  }
}
const lineDeltas = (lines, sign) => {
  const m = {};
  (lines || []).forEach((l) => { if (l.sku) m[l.sku] = (m[l.sku] || 0) + sign * l.q; });
  return m;
};

async function aOrder(b, me) {
  const tid = me.tid, pay = b.pay ? String(b.pay) : null;
  if (pay) {
    if (me.role === "waiter") throw bad("Waiters cannot take payment.");
    if (!PAYS.includes(pay)) throw bad("Choose a payment method.");
  }
  const raw = Array.isArray(b.lines) ? b.lines : [];
  if (!raw.length || raw.length > 60) throw bad("Add items first.");
  const name = str(b.name, 80), phone = str(b.phone, 30), ref = str(b.ref, 60);
  if (pay && digits(phone).length < 9) throw bad("Enter the guest's phone number. It prints on the receipt.");
  if (pay === "Room" && !ref) throw bad("Enter the room number first.");

  let old = null;
  if (b.id) {
    old = await get(tKey(tid, "orders", str(b.id, 40)));
    if (!old) throw bad("Bill not found.");
    if (old.status !== "open") throw bad("This bill is already closed.");
  }
  const menu = {}; (await list(tKey(tid, "menu") + ":")).forEach((m) => (menu[m.id] = m));
  const oldLines = {}; (old ? old.lines : []).forEach((l) => (oldLines[l.id] = l));

  const lines = [];
  for (const l of raw) {
    const id = str(l.id, 40), q = Math.round(+l.q);
    if (!id || !(q >= 1) || q > 999) throw bad("Check the quantities.");
    const m = menu[id], o = oldLines[id];
    if (m) lines.push({ id, n: m.name, p: m.price, q, d: m.dept, sku: m.sku || "" });
    else if (o) lines.push({ id, n: o.n, p: o.p, q, d: o.d, sku: o.sku || "" });
    else throw bad("An item is no longer on the menu. Clear the bill and start again.");
  }
  const total = Math.round(lines.reduce((a, l) => a + l.p * l.q, 0) * 100) / 100;

  const deltas = lineDeltas(lines, -1);
  if (old) { const back = lineDeltas(old.lines, 1); for (const k in back) deltas[k] = (deltas[k] || 0) + back[k]; }
  await moveStock(tid, deltas);

  let o;
  if (old) o = old;
  else {
    const seq = ((await get(tKey(tid, "seq"))) || { n: 0 }); seq.n++; await put(tKey(tid, "seq"), seq);
    o = { id: uid(), no: seq.n, ts: now(), by: me.name, status: "open" };
  }
  Object.assign(o, { lines, total, name, phone, ref });
  if (pay) Object.assign(o, { status: "paid", pay, paidTs: now(), cashier: me.name });
  await put(tKey(tid, "orders", o.id), o);
  return { o };
}

async function aVoid(b, me) {
  need(me, SEN);
  const o = await get(tKey(me.tid, "orders", str(b.id, 40)));
  if (!o) throw bad("Bill not found.");
  if (o.status === "void") throw bad("Already voided.");
  await moveStock(me.tid, lineDeltas(o.lines, 1));
  o.status = "void"; o.voidBy = me.name; o.voidTs = now();
  await put(tKey(me.tid, "orders", o.id), o);
  return { ok: true };
}

/* ---------- router ---------- */
const PUBLIC = { status: aStatus, setup: aSetup, login: aLogin, signup: aSignup, pub: aPub, book: aBook };
const PLATFORM = { p_approve: aPApprove, p_reject: aPReject, p_create: aPCreate, p_status: aPStatus, p_reset: aPReset, p_plan: aPPlan, p_paid: aPPaid, p_settings: aPSettings };
const HOTEL = { cfg: aCfg, add: aAdd, upd: aUpd, del: aDel, order: aOrder, void: aVoid };

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const send = (code, obj) => res.status(code).json(obj);
  try {
    if (req.method !== "POST") return send(405, { err: "Use POST." });
    let b = req.body;
    if (typeof b === "string") { try { b = JSON.parse(b); } catch (e) { b = {}; } }
    b = b && typeof b === "object" ? b : {};
    const a = String(b.a || "");
    const ip = String((req.headers["x-forwarded-for"] || "").split(",")[0] || req.socket?.remoteAddress || "ip").trim();

    if (PUBLIC[a]) return send(200, await PUBLIC[a](b, ip));

    const me = await session(b);
    if (a === "sync") return send(200, await aSync(b, me));
    if (PLATFORM[a]) { if (me.role !== "platform") throw bad("Not allowed."); return send(200, await PLATFORM[a](b, me)); }
    if (HOTEL[a]) { if (me.role === "platform") throw bad("Not allowed."); return send(200, await HOTEL[a](b, me)); }
    return send(400, { err: "Unknown request." });
  } catch (e) {
    if (e instanceof HttpErr) return send(e.code, { err: e.message });
    console.error(e);
    return send(500, { err: "Server error. Please try again." });
  }
};

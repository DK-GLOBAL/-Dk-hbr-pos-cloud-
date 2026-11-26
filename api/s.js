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
const r2 = (n) => Math.round((+n || 0) * 100) / 100;
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
// newest first; pages through Supabase's 1000-row limit up to `limit` rows
async function list(prefix, limit = 1000) {
  const out = [];
  while (out.length < limit) {
    const n = Math.min(1000, limit - out.length);
    const r = await sb("GET", `?k=like.${enc(prefix + "*")}&select=k,v&order=updated_at.desc,k.asc&limit=${n}&offset=${out.length}`);
    r.forEach((x) => out.push(x.v));
    if (r.length < n) break;
  }
  return out;
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
  const body = b64(JSON.stringify(Object.assign({ iat: now(), exp: now() + 12 * 3600 * 1000 }, p)));
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
const ROLES = ["waiter", "reception", "cashier", "supervisor", "manager", "director", "owner"];
const SEN = ["owner", "director", "manager", "supervisor"];   // stock, menu, voids, reports
const STF = ["owner", "director", "manager"];                  // staff, settings, audit trail
const TOP = ["owner", "director"];                              // may create/remove managers and directors
const rank = (r) => ROLES.indexOf(r);
const DEPTS = ["Restaurant", "Bar", "Spa", "Hotel"];
const PAYS = ["Cash", "M-Pesa", "Card", "Room"];
const BSTAT = ["Requested", "Confirmed", "Arrived", "Done", "Cancelled"];
const MODS = ["bookings", "inventory", "stocktake", "menu", "reports", "audit", "staff"];
const DEFAULT_TAG = "Welcome. Book your room, table or treatment online and we will confirm with you.";

/* ---------- settings helpers ---------- */
const vatOf = (c, set) => {
  const v = c && c.vat != null ? +c.vat : set && set.vat != null ? +set.vat : 16;
  return isFinite(v) ? v : 16;
};
function featFor(set, t) {
  const d = (set && set.feat) || {}, o = (t && t.feat) || {}, f = {};
  MODS.forEach((k) => { f[k] = o[k] !== undefined ? o[k] : d[k] !== false; });
  return f;
}

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
    if (a.since && (p.iat || 0) < a.since) throw E(401, "Please sign in again.");
    return { role: "platform", name: a.name, email: a.email };
  }
  const t = await get("p:tenant:" + p.tid);
  if (!t) throw E(401, "Please sign in again.");
  if (t.status !== "active") throw E(403, "This account is suspended. Contact DK Global Tech.");
  if (p.r === "owner") return { role: "owner", name: t.owner, tid: t.id, t };
  const s = await get(tKey(t.id, "staff", p.sid));
  if (!s) throw E(401, "Your access was removed.");
  if (s.suspended) throw E(401, "Your account is suspended. Contact your manager.");
  return { role: s.role, name: s.name, tid: t.id, sid: s.id, t };
}
async function audit(me, act, detail) {
  try {
    const id = String(now()).padStart(14, "0") + "-" + uid();
    await put(tKey(me.tid, "audit", id), { id, ts: now(), who: me.name, role: me.role, act, d: str(detail, 300) });
  } catch (e) { console.error("audit", e); }
}
async function paudit(who, act, detail) {   // platform admin audit trail
  try {
    const id = String(now()).padStart(14, "0") + "-" + uid();
    await put("p:audit:" + id, { id, ts: now(), who: str(who, 80), act, d: str(detail, 300) });
  } catch (e) { console.error("paudit", e); }
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
  await paudit(name, "Sign in", "Platform admin account created");
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
      if (!checkPw(pw, admin.hash)) { await paudit(admin.name, "Failed sign in", "Wrong password for " + email); return fail(); }
      await lockClear(lk);
      await paudit(admin.name, "Sign in", "Platform admin sign in");
      return { t: sign({ r: "platform", e: email }), me: { name: admin.name, role: "platform" } };
    }
    const t = (await allTenants()).find((x) => x.email === email);
    if (t) {
      if (!checkPw(pw, t.ownerHash)) return fail();
      if (t.status !== "active") throw E(401, "This account is suspended. Contact DK Global Tech.");
      await lockClear(lk);
      await audit({ tid: t.id, name: t.owner, role: "owner" }, "Sign in", "Owner sign in");
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
  if (staff.suspended) throw E(401, "Your account is suspended. Contact your manager.");
  await lockClear(lk);
  await audit({ tid: t.id, name: staff.name, role: staff.role }, "Sign in", "Staff sign in");
  return { t: sign({ r: "staff", tid: t.id, sid: staff.id }), me: { name: staff.name, role: staff.role } };
}

async function aSignup(b, ip) {
  await lockCheck("su:" + sha(ip), 6, 3600e3);
  const x = cleanSignup(b);
  if (await emailTaken(x.email)) throw bad("That email is already registered or waiting for approval.");
  const id = uid();
  await put("p:req:" + id, { id, name: x.name, owner: x.owner, email: x.email, phone: x.phone, loc: x.loc, hash: hashPw(x.pw), status: "pending", ts: now() });
  await lockHit("su:" + sha(ip), 3600e3);
  await paudit(x.owner, "Request received", `${x.name} (${x.email})`);
  return { ok: true };
}

async function aPub(b) {
  const t = await tenantBySlug(b.h);
  if (!t || t.status !== "active") throw E(404, "Hotel not found. Check the link.");
  const c = (await get(tKey(t.id, "cfg"))) || {};
  const menu = (await list(tKey(t.id, "menu") + ":")).map((m) => ({ id: m.id, name: m.name, price: m.price, dept: m.dept }));
  return { name: c.name || t.name, tag: c.tag || DEFAULT_TAG, phone: c.phone || t.phone || "", addr: c.addr || t.loc || "", menu };
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

// The website chat agent. No AI key is wired in here, so it tells the page to use its built-in answers.
async function aAi() { return { fallback: true }; }

// Order placed by a guest through the website chat agent. It lands as an open bill for staff.
async function aGOrder(b, ip) {
  const t = await tenantBySlug(b.h);
  if (!t || t.status !== "active") throw E(404, "Hotel not found. Check the link.");
  await lockCheck("go:" + sha(ip), 15, 3600e3);
  const name = str(b.name, 80), phone = str(b.phone, 30), where = str(b.where, 60);
  if (!name) throw bad("Enter your name.");
  if (digits(phone).length < 9) throw bad("Enter a valid phone number.");
  const raw = Array.isArray(b.lines) ? b.lines.slice(0, 40) : [];
  if (!raw.length) throw bad("Add items first.");
  const menu = {}; (await list(tKey(t.id, "menu") + ":")).forEach((m) => (menu[m.id] = m));
  const lines = [];
  for (const l of raw) {
    const m = menu[str(l.id, 40)], q = Math.round(+l.q);
    if (!m || !(q >= 1) || q > 99) throw bad("An item is no longer on the menu. Please start the order again.");
    lines.push({ id: m.id, n: m.name, p: m.price, q, d: m.dept, sku: m.sku || "" });
  }
  const total = r2(lines.reduce((a, l) => a + l.p * l.q, 0));
  await moveStock(t.id, lineDeltas(lines, -1));
  const seq = (await get(tKey(t.id, "seq"))) || { n: 0 }; seq.n++; await put(tKey(t.id, "seq"), seq);
  const c = (await get(tKey(t.id, "cfg"))) || {}, set = (await get("p:settings")) || {};
  const ref = "OR" + crypto.randomBytes(3).toString("hex").toUpperCase();
  const o = { id: uid(), no: seq.n, ts: now(), by: "Online guest", status: "open", lines, total, name, phone,
    ref: where || "Online order", gref: ref, online: true, vr: vatOf(c, set) };
  await put(tKey(t.id, "orders", o.id), o);
  await audit({ tid: t.id, name: "Online guest", role: "guest" }, "Bill saved", `#${o.no} KSh ${total} (online order ${ref})`);
  await lockHit("go:" + sha(ip), 3600e3);
  return { ref, total };
}

/* ---------- actions: platform admin ---------- */
async function pReq(id) {
  const r = id ? await get("p:req:" + id) : null;
  if (!r) throw bad("Request not found.");
  return r;
}
async function aPApprove(b, me) {
  const r = await pReq(b.id);
  if (r.status !== "pending") throw bad("This request was already handled.");
  const pk = cleanPkg(b);
  const t = await createTenant(r, r.hash, pk);
  await put("p:req:" + r.id, Object.assign({}, r, { status: "approved", hash: "", ts2: now() }));
  await paudit(me.name, "Request approved", `${r.name} (code ${t.slug}), ${pk.plan} KSh ${pk.fee} ${pk.period}`);
  return { ok: true, slug: t.slug, id: t.id };
}
async function aPReject(b, me) {
  const r = await pReq(b.id);
  if (r.status !== "pending") throw bad("This request was already handled.");
  await put("p:req:" + r.id, Object.assign({}, r, { status: "rejected", ts2: now() }));
  await paudit(me.name, "Request rejected", `${r.name} (${r.email})`);
  return { ok: true };
}
async function aPCreate(b, me) {
  const x = cleanSignup(b), pk = cleanPkg(b);
  if (await emailTaken(x.email)) throw bad("That email is already registered.");
  const t = await createTenant(x, hashPw(x.pw), pk);
  await paudit(me.name, "Client created", `${x.name} (code ${t.slug}), ${pk.plan} KSh ${pk.fee} ${pk.period}`);
  return { ok: true, slug: t.slug, id: t.id };
}
async function aPStatus(b, me) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null;
  if (!t) throw bad("Client not found.");
  if (!["active", "suspended"].includes(b.status)) throw bad("Invalid status.");
  t.status = b.status; await put("p:tenant:" + t.id, t);
  await paudit(me.name, b.status === "active" ? "Client activated" : "Client suspended", t.name);
  return { ok: true };
}
async function aPPlan(b, me) {
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
  await paudit(me.name, "Package saved", `${t.name}: ${t.plan}, KSh ${t.fee} ${t.period}`);
  return { ok: true };
}
async function aPPaid(b, me) {
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
  await paudit(me.name, "Marked paid", `${t.name}: ${t.plan}, KSh ${t.fee} ${t.period}`);
  return { ok: true };
}
async function aPSettings(b, me) {
  const site = str(b.site, 200).replace(/\/+$/, "");
  if (site && !/^https?:\/\//i.test(site)) throw bad("The site address must start with https://");
  const cur = (await get("p:settings")) || {};   // keep defaults saved by "Save defaults"
  await put("p:settings", Object.assign(cur, { pay: str(b.pay, 600), contact: str(b.contact, 120), site }));
  await paudit(me.name, "Payment details saved", "Payment instructions, contact and site address updated");
  return { ok: true };
}
async function aPReset(b, me) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null;
  if (!t) throw bad("Client not found.");
  if (String(b.pw || "").length < 8) throw bad("Password must be at least 8 characters.");
  t.ownerHash = hashPw(b.pw); await put("p:tenant:" + t.id, t);
  await paudit(me.name, "Client password reset", t.name);
  return { ok: true };
}
async function aPProfile(b, me) {
  const name = str(b.name, 80);
  if (!name) throw bad("Enter your name.");
  const a = await get("p:admin");
  if (!a) throw bad("Admin not found.");
  const old = a.name;
  a.name = name; await put("p:admin", a);
  await paudit(name, "Name changed", `${old} to ${name}`);
  return { ok: true, name };
}
async function aPDefaults(b, me) {
  const vat = Number(b.vat);
  if (b.vat === "" || b.vat == null || !isFinite(vat) || vat < 0 || vat > 100) throw bad("Enter a valid VAT %, between 0 and 100.");
  const depts = [...new Set(String(b.depts || "").split(",").map((s) => str(s, 24)).filter(Boolean))];
  if (depts.length < 1 || depts.length > 8) throw bad("Enter 1 to 8 sections, separated by commas.");
  const feat = {};
  MODS.forEach((k) => { feat[k] = !(b.feat && b.feat[k] === false); });
  const cur = (await get("p:settings")) || {};
  await put("p:settings", Object.assign(cur, { vat, depts, feat }));
  await paudit(me.name, "Defaults saved", `VAT ${vat}%, sections: ${depts.join(", ")}`);
  return { ok: true };
}
async function aPTFeat(b, me) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null;
  if (!t) throw bad("Client not found.");
  const f = {};   // "def" means follow the platform default, so it is simply not stored
  MODS.forEach((k) => { const v = b.feat && b.feat[k]; if (v === "on" || v === true) f[k] = true; else if (v === "off" || v === false) f[k] = false; });
  t.feat = f; await put("p:tenant:" + t.id, t);
  const off = MODS.filter((k) => f[k] === false).join(", ");
  await paudit(me.name, "Client features saved", `${t.name}${off ? ": off - " + off : ": all default"}`);
  return { ok: true };
}
async function aPPw(b, me) {
  const a = await get("p:admin");
  if (!a) throw bad("Admin not found.");
  if (!checkPw(String(b.cur || ""), a.hash)) throw bad("Your current password is wrong.");
  if (String(b.pw || "").length < 8) throw bad("New password must be at least 8 characters.");
  a.hash = hashPw(b.pw); a.since = now();   // signs out every other device
  await put("p:admin", a);
  await paudit(a.name, "Password changed", "Platform admin password changed; other devices signed out");
  return { ok: true, t: sign({ r: "platform", e: a.email }) };
}
async function aSignoutAll(b, me) {
  const a = await get("p:admin");
  if (!a) throw bad("Admin not found.");
  a.since = now(); await put("p:admin", a);
  await paudit(a.name, "Signed out of all devices", "All platform admin sessions ended");
  return { ok: true };
}

/* ---------- actions: hotel ---------- */
async function aSync(b, me) {
  if (me.role === "platform") {
    const reqs = (await list("p:req:")).filter((r) => r.status === "pending" || r.status === "rejected")
      .map((r) => ({ id: r.id, name: r.name, owner: r.owner, email: r.email, phone: r.phone, loc: r.loc, status: r.status, ts: r.ts }))
      .sort((a, c) => c.ts - a.ts);
    const tenants = (await allTenants()).map((t) => ({ id: t.id, slug: t.slug, name: t.name, owner: t.owner, email: t.email, phone: t.phone, status: t.status, ts: t.ts,
      plan: t.plan || "", fee: t.fee || 0, period: t.period || "month", paidUntil: t.paidUntil || 0, feat: t.feat || {} }))
      .sort((a, c) => c.ts - a.ts);
    const aud = (await list("p:audit:", 300)).sort((a, z) => z.ts - a.ts);
    return { me: { name: me.name, role: "platform" }, reqs, tenants, pset: (await get("p:settings")) || {}, audit: aud };
  }
  const tid = me.tid, sen = SEN.includes(me.role);
  const [c, set, menu, orders, bookings, stock, staff, aud] = await Promise.all([
    get(tKey(tid, "cfg")), get("p:settings"), list(tKey(tid, "menu") + ":"), list(tKey(tid, "orders") + ":", 300),
    list(tKey(tid, "bookings") + ":", 300), sen ? list(tKey(tid, "stock") + ":") : [], STF.includes(me.role) ? list(tKey(tid, "staff") + ":") : [],
    STF.includes(me.role) ? list(tKey(tid, "audit") + ":", 250) : [],
  ]);
  const byName = (a, z) => String(a.name).localeCompare(String(z.name));
  let pkg;
  if (STF.includes(me.role)) {
    const ps = set || {};
    pkg = { plan: me.t.plan || "", fee: me.t.fee || 0, period: me.t.period || "month", paidUntil: me.t.paidUntil || 0, pay: ps.pay || "" };
  }
  const cc = c || {};
  return {
    me: { name: me.name, role: me.role }, slug: me.t.slug, pkg,
    vat: vatOf(cc, set), feat: featFor(set, me.t),
    cfg: { name: cc.name || me.t.name, phone: cc.phone || "", addr: cc.addr || "", tag: cc.tag || "",
      pin: cc.pin || "", email: cc.email || "", thanks: cc.thanks || "", foot: cc.foot || "", extra: cc.extra || "" },
    menu: menu.sort(byName),
    orders: orders.sort((a, z) => z.ts - a.ts),
    bookings,
    stock: stock.sort(byName),
    audit: aud.sort((a, z) => z.ts - a.ts),
    at: now(),
    staff: staff.map((s) => ({ id: s.id, name: s.name, role: s.role, suspended: !!s.suspended })).sort(byName),
  };
}

async function aCfg(b, me) {
  need(me, STF);
  const name = str(b.name, 80);
  if (!name) throw bad("Enter the hotel name.");
  const c = Object.assign({}, (await get(tKey(me.tid, "cfg"))) || {});
  Object.assign(c, {
    name, phone: str(b.phone, 30), addr: str(b.addr, 120), tag: str(b.tag, 200),
    pin: str(b.pin, 30), email: str(b.email, 100), thanks: str(b.thanks, 120), foot: str(b.foot, 160), extra: str(b.extra, 600),
  });
  if (b.vat === undefined || b.vat === null || b.vat === "") delete c.vat;   // blank = follow the platform default
  else {
    const v = Number(b.vat);
    if (!isFinite(v) || v < 0 || v > 100) throw bad("Enter a valid VAT %, between 0 and 100.");
    c.vat = v;
  }
  await put(tKey(me.tid, "cfg"), c);
  await audit(me, "Settings", "Hotel details changed");
  return { ok: true };
}

async function aAdd(b, me) {
  const c = b.c, it = b.item || {};
  if (c === "stock") {
    need(me, SEN);
    const name = str(it.name, 80); if (!name) throw bad("Enter an item name.");
    const o = { id: uid(), name, qty: +it.qty || 0, unit: str(it.unit, 20) || "unit", min: +it.min || 0 };
    await put(tKey(me.tid, "stock", o.id), o);
    await audit(me, "Stock added", `${o.name}: ${o.qty} ${o.unit}`); return { ok: true, id: o.id };
  }
  if (c === "menu") {
    need(me, SEN);
    const name = str(it.name, 80), price = +it.price;
    if (!name || !(price > 0)) throw bad("Enter a name and a price.");
    if (!DEPTS.includes(it.dept)) throw bad("Choose a section.");
    let sku = str(it.sku, 40);
    if (sku && !(await get(tKey(me.tid, "stock", sku)))) sku = "";
    const o = { id: uid(), name, price, dept: it.dept, sku };
    await put(tKey(me.tid, "menu", o.id), o);
    await audit(me, "Menu added", `${o.name} KSh ${o.price}`); return { ok: true, id: o.id };
  }
  if (c === "staff") {
    need(me, STF);
    const name = str(it.name, 60), pin = String(it.pin || "").trim(), role = it.role;
    if (!name) throw bad("Enter the staff name.");
    if (!/^\d{4,8}$/.test(pin)) throw bad("PIN must be 4 to 8 digits.");
    if (!ROLES.includes(role)) throw bad("Choose a role.");
    if (role === "owner" && me.role !== "owner") throw bad("Only the owner can add another owner.");
    if (rank(role) >= rank("manager") && !TOP.includes(me.role)) throw bad("Only the owner or a director can add a manager or director.");
    if ((await list(tKey(me.tid, "staff") + ":")).some((s) => lc(s.name) === lc(name))) throw bad("Someone with that name already exists.");
    const o = { id: uid(), name, role, pinHash: hashPw(pin) };
    await put(tKey(me.tid, "staff", o.id), o);
    await audit(me, "Staff added", `${o.name} (${o.role})`); return { ok: true, id: o.id };
  }
  throw bad("Unknown item type.");
}

async function aUpd(b, me) {
  const c = b.c, id = str(b.id, 40), patch = b.patch || {};
  if (c === "bookings") {
    const o = await get(tKey(me.tid, "bookings", id)); if (!o) throw bad("Booking not found.");
    if (!BSTAT.includes(patch.status)) throw bad("Invalid status.");
    o.status = patch.status; await put(tKey(me.tid, "bookings", id), o);
    await audit(me, "Booking", `${o.ref} to ${o.status}`); return { ok: true };
  }
  if (c === "staff") {
    need(me, STF);
    const s = await get(tKey(me.tid, "staff", id)); if (!s) throw bad("Staff member not found.");
    if (rank(s.role) >= rank("manager") && !TOP.includes(me.role)) throw bad("Only the owner or a director can change a manager.");
    if (patch.pin !== undefined) {
      if (!/^\d{4,8}$/.test(String(patch.pin))) throw bad("PIN must be 4 to 8 digits.");
      s.pinHash = hashPw(String(patch.pin)); await audit(me, "PIN reset", s.name);
    }
    if (patch.role !== undefined) {
      if (!ROLES.includes(patch.role) || patch.role === "owner") throw bad("Choose a role.");
      if (rank(patch.role) >= rank("manager") && !TOP.includes(me.role)) throw bad("Only the owner or a director can make a manager.");
      await audit(me, "Role changed", `${s.name}: ${s.role} to ${patch.role}`); s.role = patch.role;
    }
    if (patch.suspended !== undefined) {
      if (id === me.sid) throw bad("You cannot suspend yourself.");
      s.suspended = !!patch.suspended;
      await audit(me, s.suspended ? "Staff suspended" : "Staff reinstated", s.name);
    }
    await put(tKey(me.tid, "staff", id), s); return { ok: true };
  }
  need(me, SEN);
  if (c === "stock") {
    const o = await get(tKey(me.tid, "stock", id)); if (!o) throw bad("Stock item not found.");
    const d = +patch.delta; if (!d || !isFinite(d)) throw bad("Enter a number, like 24 or -3.");
    const before = o.qty; o.qty = Math.round((o.qty + d) * 1000) / 1000; await put(tKey(me.tid, "stock", id), o);
    await audit(me, d > 0 ? "Stock in" : "Stock out", `${o.name}: ${d > 0 ? "+" : ""}${d} (${before} to ${o.qty} ${o.unit})${patch.why ? " - " + str(patch.why, 80) : ""}`); return { ok: true };
  }
  if (c === "menu") {
    const o = await get(tKey(me.tid, "menu", id)); if (!o) throw bad("Menu item not found.");
    if (patch.name !== undefined) o.name = str(patch.name, 80) || o.name;
    if (patch.price !== undefined && +patch.price > 0) o.price = +patch.price;
    if (patch.dept !== undefined && DEPTS.includes(patch.dept)) o.dept = patch.dept;
    await put(tKey(me.tid, "menu", id), o); await audit(me, "Menu edited", `${o.name} KSh ${o.price}`); return { ok: true };
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
    if (s && rank(s.role) >= rank("manager") && !TOP.includes(me.role)) throw bad("Only the owner or a director can remove a manager.");
  }
  const gone = await get(tKey(me.tid, c, id));
  await del(tKey(me.tid, c, id));
  await audit(me, c === "staff" ? "Staff removed" : c === "menu" ? "Menu deleted" : "Stock deleted", gone ? gone.name : id);
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
  const tid = me.tid;
  let pay = b.pay ? String(b.pay) : null, pays = null;
  if (pay && me.role === "waiter") throw bad("Waiters cannot take payment.");
  const raw = Array.isArray(b.lines) ? b.lines : [];
  if (!raw.length || raw.length > 60) throw bad("Add items first.");
  const name = str(b.name, 80), phone = str(b.phone, 30), ref = str(b.ref, 60);

  const cid = /^[a-z0-9]{8,24}$/i.test(String(b.cid || "")) ? String(b.cid) : "";
  if (cid && !b.id) { const dup = await get(tKey(tid, "orders", cid)); if (dup) return { o: dup, dup: true }; }
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
  const total = r2(lines.reduce((a, l) => a + l.p * l.q, 0));

  if (pay) {
    if (Array.isArray(b.pays) && b.pays.length) {            // split or mixed payment
      pays = b.pays.slice(0, 6).map((p) => ({ m: String(p.m), a: r2(p.a), r: str(p.r, 40) }));
      if (pays.some((p) => !PAYS.includes(p.m) || !(p.a > 0))) throw bad("Check the payment methods and amounts.");
      if (Math.abs(r2(pays.reduce((a, p) => a + p.a, 0)) - total) > 0.01) throw bad("The payments must add up to the bill total.");
      pay = pays.length === 1 ? pays[0].m : "Split";
    } else if (!PAYS.includes(pay)) throw bad("Choose a payment method.");
    if (digits(phone).length < 9) throw bad("Enter the guest's phone number. It prints on the receipt.");
    if ((pay === "Room" || (pays && pays.some((p) => p.m === "Room"))) && !ref) throw bad("Enter the room number first.");
  }

  const deltas = lineDeltas(lines, -1);
  if (old) { const back = lineDeltas(old.lines, 1); for (const k in back) deltas[k] = (deltas[k] || 0) + back[k]; }
  await moveStock(tid, deltas);

  const set = (await get("p:settings")) || {}, cf = (await get(tKey(tid, "cfg"))) || {};
  let o;
  if (old) o = old;
  else {
    const seq = ((await get(tKey(tid, "seq"))) || { n: 0 }); seq.n++; await put(tKey(tid, "seq"), seq);
    o = { id: cid || uid(), no: seq.n, ts: now(), by: me.name, status: "open" };
    if (b.off) { o.off = true; o.madeTs = Math.min(now(), +b.off || now()); o.ts = o.madeTs; }
  }
  Object.assign(o, { lines, total, name, phone, ref, vr: vatOf(cf, set) });
  if (pay) {
    Object.assign(o, { status: "paid", pay, paidTs: o.madeTs || now(), cashier: me.name });
    if (pays) o.pays = pays; else delete o.pays;
  }
  await put(tKey(tid, "orders", o.id), o);
  await audit(me, pay ? "Bill paid" : old ? "Bill updated" : "Bill saved", `#${o.no} KSh ${total}${pay ? " by " + pay : ""}${b.off ? " (made offline)" : ""}`);
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
  await audit(me, "Bill voided", `#${o.no} KSh ${o.total}`);
  return { ok: true };
}

/* sales report for any date range: day, week, month, year, custom */
async function aReport(b, me) {
  need(me, SEN);
  const from = +b.from, to = +b.to, tz = +b.tz || 0;
  if (!isFinite(from) || !isFinite(to) || to < from) throw bad("Choose a valid date range.");
  if (to - from > 400 * 864e5) throw bad("Please choose a range of 13 months or less.");
  const [orders, c, set] = await Promise.all([list(tKey(me.tid, "orders") + ":", 5000), get(tKey(me.tid, "cfg")), get("p:settings")]);
  const defVat = vatOf(c || {}, set || {});
  const inR = (t) => t >= from && t <= to;
  const pay = {}, dept = {}, server = {}, cashier = {}, items = {}, daily = {};
  let gross = 0, vat = 0, count = 0, voidN = 0, voidT = 0, openN = 0, openT = 0;
  const add = (m, k, v) => { m[k] = (m[k] || 0) + v; };
  for (const o of orders) {
    if (o.status === "paid") {
      const t = o.paidTs || o.ts;
      if (!inR(t)) continue;
      count++; gross += o.total;
      const vr = o.vr != null ? +o.vr : defVat;
      vat += o.total * vr / (100 + vr);
      const ps = o.pays && o.pays.length ? o.pays : [{ m: o.pay || "Other", a: o.total }];
      ps.forEach((p) => add(pay, p.m === "Room" ? "Room charge" : p.m, +p.a || 0));
      add(server, o.by || "-", o.total);
      add(cashier, o.cashier || "-", o.total);
      (o.lines || []).forEach((l) => {
        add(dept, l.d || "Other", l.p * l.q);
        const it = items[l.n] || (items[l.n] = [0, 0]); it[0] += l.q; it[1] += l.p * l.q;
      });
      const day = new Date(t - tz * 60000).toISOString().slice(0, 10);
      const dd = daily[day] || (daily[day] = [0, 0]); dd[0]++; dd[1] += o.total;
    } else if (o.status === "void") {
      if (inR(o.voidTs || o.ts)) { voidN++; voidT += o.total; }
    } else if (o.status === "open") {
      if (inR(o.ts)) { openN++; openT += o.total; }
    }
  }
  const rank2 = (m) => Object.entries(m).sort((a, z) => z[1] - a[1]).map(([k, v]) => [k, r2(v)]);
  return {
    gross: r2(gross), net: r2(gross - vat), vat: r2(vat), count, avg: count ? r2(gross / count) : 0,
    voids: { n: voidN, total: r2(voidT) }, open: { n: openN, total: r2(openT) },
    pay: rank2(pay), dept: rank2(dept), server: rank2(server), cashier: rank2(cashier),
    items: Object.entries(items).sort((a, z) => z[1][1] - a[1][1]).slice(0, 25).map(([n, v]) => [n, v[0], r2(v[1])]),
    daily: Object.entries(daily).sort((a, z) => a[0].localeCompare(z[0])).map(([k, v]) => [k, v[0], r2(v[1])]),
  };
}

/* ---------- router ---------- */
const PUBLIC = { status: aStatus, setup: aSetup, login: aLogin, signup: aSignup, pub: aPub, book: aBook, ai: aAi, gorder: aGOrder };
const PLATFORM = {
  p_approve: aPApprove, p_reject: aPReject, p_create: aPCreate, p_status: aPStatus, p_reset: aPReset, p_plan: aPPlan, p_paid: aPPaid,
  p_settings: aPSettings, p_profile: aPProfile, p_defaults: aPDefaults, p_tfeat: aPTFeat, p_pw: aPPw, signout_all: aSignoutAll,
};
const HOTEL = { cfg: aCfg, add: aAdd, upd: aUpd, del: aDel, order: aOrder, void: aVoid, report: aReport };

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

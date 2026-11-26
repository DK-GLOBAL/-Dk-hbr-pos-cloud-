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
  const body = b64(JSON.stringify(Object.assign({ iat: now(), exp: now() + 30 * 864e5 }, p)));
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
const svOf = (x) => (x && x.sv) || 0;
async function session(b) {
  const p = unsign(b.t);
  if (!p) throw E(401, "Please sign in again.");
  if (p.r === "platform") {
    const a = await get("p:admin");
    if (!a || a.email !== p.e || svOf(a) !== (p.sv || 0)) throw E(401, "Please sign in again.");
    if (b.as) {   // platform admin works inside a client's workspace with every right
      const t = await get("p:tenant:" + str(b.as, 40));
      if (!t) throw bad("Client not found.");
      return { role: "owner", name: a.name + " (platform)", tid: t.id, t, plat: true, _p: p, _a: a };
    }
    return { role: "platform", name: a.name, _p: p, _a: a };
  }
  const t = await get("p:tenant:" + p.tid);
  if (!t) throw E(401, "Please sign in again.");
  if (t.status !== "active") throw E(403, "This account is suspended. Contact DK Global Tech.");
  if (p.r === "owner") {
    if (svOf(t) !== (p.sv || 0)) throw E(401, "Please sign in again.");
    return { role: "owner", name: t.owner, tid: t.id, t, _p: p };
  }
  const s = await get(tKey(t.id, "staff", p.sid));
  if (!s || svOf(s) !== (p.sv || 0)) throw E(401, "Your access was removed.");
  return { role: s.role, name: s.name, tid: t.id, sid: s.id, t, _p: p, _s: s };
}
async function audit(me, act, detail) {
  try {
    const id = String(now()).padStart(14, "0") + "-" + uid();
    await put(tKey(me.tid, "audit", id), { id, ts: now(), who: me.name, role: me.plat ? "platform" : me.role, act, d: str(detail, 300) });
  } catch (e) { console.error("audit", e); }
}
const need = (me, roles) => { if (!roles.includes(me.role)) throw bad("Your role cannot do this."); };

/* ---------- features, sections, VAT ---------- */
const MODS = ["bookings", "inventory", "stocktake", "menu", "reports", "audit", "staff"];
const pset = async () => (await get("p:settings")) || {};
function featMap(ps, t) { const o = {}; MODS.forEach((k) => { const tv = t && t.feat && t.feat[k]; o[k] = tv !== undefined ? !!tv : !(ps.feat && ps.feat[k] === false); }); return o; }
async function needFeat(me, mod) { if (me.plat) return; if (!featMap(await pset(), me.t)[mod]) throw bad("This feature is switched off for your account. Contact DK Global Tech."); }
async function deptsOf(tid, ps) { const c = (await get(tKey(tid, "cfg"))) || {}; return Array.isArray(c.depts) && c.depts.length ? c.depts : (Array.isArray(ps.depts) && ps.depts.length ? ps.depts : DEPTS); }
const vatOf = (c, ps) => (c && c.vat != null ? c.vat : ps.vat != null ? ps.vat : 16);

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
      if (!checkPw(pw, admin.hash)) { await paudit(admin.name, "Failed sign-in", "Wrong password for the platform admin"); return fail(); }
      await lockClear(lk);
      await paudit(admin.name, "Sign in", "Platform admin sign in");
      return { t: sign({ r: "platform", e: email, sv: svOf(admin) }), me: { name: admin.name, role: "platform" } };
    }
    const t = (await allTenants()).find((x) => x.email === email);
    if (t) {
      if (!checkPw(pw, t.ownerHash)) return fail();
      if (t.status !== "active") throw E(401, "This account is suspended. Contact DK Global Tech.");
      await lockClear(lk);
      await audit({ tid: t.id, name: t.owner, role: "owner" }, "Sign in", "Owner sign in");
      return { t: sign({ r: "owner", tid: t.id, sv: svOf(t) }), me: { name: t.owner, role: "owner" } };
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
  await audit({ tid: t.id, name: staff.name, role: staff.role }, "Sign in", "Staff sign in");
  return { t: sign({ r: "staff", tid: t.id, sid: staff.id, sv: svOf(staff) }), me: { name: staff.name, role: staff.role } };
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
  const menu = (await list(tKey(t.id, "menu") + ":")).map((m) => ({ id: m.id, name: m.name, price: m.price, dept: m.dept })).sort((a, z) => String(a.name).localeCompare(String(z.name)));
  return { name: c.name || t.name, tag: c.tag || DEFAULT_TAG, phone: c.phone || t.phone || "", addr: c.addr || t.loc || "", logo: c.logo || "", lw: c.lw || 0, lh: c.lh || 0, menu };
}
/* ---------- DK AI Agent: guest orders and chat ---------- */
async function aGOrder(b, ip) {
  const t = await tenantBySlug(b.h);
  if (!t || t.status !== "active") throw E(404, "Hotel not found. Check the link.");
  if (!featMap(await pset(), t).bookings) throw E(404, "Online ordering is not available for this hotel.");
  await lockCheck("go:" + sha(ip), 12, 3600e3);
  const name = str(b.name, 80), phone = str(b.phone, 30), where = str(b.where, 60);
  if (!name) throw bad("Enter your name.");
  if (digits(phone).length < 9) throw bad("Enter a valid phone number.");
  const menu = await list(tKey(t.id, "menu") + ":");
  const lines = (Array.isArray(b.lines) ? b.lines : []).slice(0, 30).map((l) => {
    const m = menu.find((x) => x.id === str(l && l.id, 40)), q = Math.min(Math.max(Math.round(+(l && l.q)) || 0, 0), 50);
    return m && q ? { n: m.name, p: m.price, q } : null;
  }).filter(Boolean);
  if (!lines.length) throw bad("Your order is empty.");
  const total = lines.reduce((a, l) => a + l.p * l.q, 0), id = uid(), ref = "OR" + crypto.randomBytes(3).toString("hex").toUpperCase();
  const eat = new Date(now() + 3 * 3600e3).toISOString();
  await put(tKey(t.id, "bookings", id), { id, ref, service: "Guest order", date: eat.slice(0, 10), time: eat.slice(11, 16), guests: 1, name, phone, email: "", notes: str(`Order: ${lines.map((l) => l.q + "x " + l.n).join(", ")} | Total KSh ${total}` + (where ? ` | For: ${where}` : ""), 500), status: "Requested", ts: now() });
  await lockHit("go:" + sha(ip), 3600e3);
  return { ref, total };
}
async function aAi(b, ip) {
  const key = process.env.ANTHROPIC_API_KEY || "";
  if (!key) return { fallback: true };
  await lockCheck("ai:" + sha(ip), 60, 3600e3);
  let sys, menu = [];
  if (b.h) {
    const t = await tenantBySlug(b.h);
    if (!t || t.status !== "active") throw E(404, "Hotel not found.");
    const c = (await get(tKey(t.id, "cfg"))) || {};
    menu = (await list(tKey(t.id, "menu") + ":")).slice(0, 120);
    sys = `You are DK AI Agent for ${c.name || t.name}. Help guests order items and answer questions about the hotel. Menu (id | name | price KSh | section):\n${menu.map((m) => `${m.id} | ${m.name} | ${m.price} | ${m.dept}`).join("\n") || "(no menu published yet)"}\nOnly offer items on this menu. When the guest has clearly decided what to order, confirm the items and add one last line exactly: ORDER_JSON:[{"id":"<id>","q":<number>}] using ids from the menu. Never add that line otherwise. The guest then enters their name and phone on the page to place the order; never ask for payment details. Hotel phone: ${c.phone || t.phone || "not listed"}. Keep answers short, plain text, no markdown. Reply in the guest's language.`;
  } else {
    sys = "You are DK AI Agent for DK HBR POS, a hotel, bar and restaurant system by DK Global Tech in Kenya. Facts: online guest booking; POS with cash, M-Pesa, card and room charge; stock that deducts on every sale with low-stock alerts; roles (owner, director, manager, supervisor, cashier, reception, waiter); full audit trail; works offline and installs on phone or computer; printable receipts showing the guest phone number; each hotel gets its own booking page; accounts are requested on the site and approved by DK Global Tech. Pricing varies, so for quotes or a demo ask the visitor to call or WhatsApp 0780490437. Never invent prices, features or promises. Keep answers short, friendly, plain text, no markdown. Reply in the user's language (English or Swahili).";
  }
  let msgs = (Array.isArray(b.msgs) ? b.msgs : []).slice(-12).map((m) => ({ role: m && m.role === "assistant" ? "assistant" : "user", content: str(m && m.content, 600) })).filter((m) => m.content);
  while (msgs.length && msgs[0].role !== "user") msgs.shift();
  if (!msgs.length) throw bad("Say something first.");
  await lockHit("ai:" + sha(ip), 3600e3);
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json" }, body: JSON.stringify({ model: process.env.AI_MODEL || "claude-sonnet-5-5", max_tokens: 500, system: sys, messages: msgs }) });
    const j = await r.json();
    let text = ((j.content || []).find((x) => x.type === "text") || {}).text || "";
    if (!r.ok || !text) return { fallback: true };
    let order = null;
    const m = text.match(/ORDER_JSON:\s*(\[[\s\S]*\])/);
    if (m) {
      text = text.replace(m[0], "").trim();
      try { order = JSON.parse(m[1]).map((o) => ({ id: str(o.id, 40), q: Math.min(Math.max(Math.round(+o.q) || 1, 1), 50) })).filter((o) => menu.some((x) => x.id === o.id)); } catch (e) { order = null; }
    }
    return { reply: text, order };
  } catch (e) { console.error("ai", e); return { fallback: true }; }
}

async function aBook(b, ip) {
  const t = await tenantBySlug(b.h);
  if (!t || t.status !== "active") throw E(404, "Hotel not found. Check the link.");
  if (!featMap(await pset(), t).bookings) throw E(404, "Online booking is not available for this hotel.");
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
  await put("p:settings", Object.assign({}, await pset(), { pay: str(b.pay, 600), contact: str(b.contact, 120), site }));
  return { ok: true };
}
async function aPReset(b) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null;
  if (!t) throw bad("Client not found.");
  if (String(b.pw || "").length < 8) throw bad("Password must be at least 8 characters.");
  t.ownerHash = hashPw(b.pw); t.sv = svOf(t) + 1; await put("p:tenant:" + t.id, t);
  return { ok: true };
}

async function aPDefaults(b) {
  const ps = await pset(), n = Object.assign({}, ps);
  if (b.vat !== undefined) { const v = Number(b.vat); if (!isFinite(v) || v < 0 || v > 30) throw bad("VAT must be between 0 and 30."); n.vat = Math.round(v * 100) / 100; }
  if (b.depts !== undefined) { const d = [...new Set((Array.isArray(b.depts) ? b.depts : String(b.depts).split(",")).map((x) => str(x, 20)).filter(Boolean))]; if (!d.length || d.length > 8) throw bad("Enter 1 to 8 sections."); n.depts = d; }
  if (b.feat && typeof b.feat === "object") { n.feat = Object.assign({}, ps.feat || {}); MODS.forEach((k) => { if (k in b.feat) n.feat[k] = !!b.feat[k]; }); }
  await put("p:settings", n); return { ok: true };
}
async function aPTFeat(b) {
  const t = b.id ? await get("p:tenant:" + str(b.id, 40)) : null; if (!t) throw bad("Client not found.");
  t.feat = t.feat || {}; const f = b.feat && typeof b.feat === "object" ? b.feat : {};
  MODS.forEach((k) => { if (k in f) { if (f[k] === "on") t.feat[k] = true; else if (f[k] === "off") t.feat[k] = false; else delete t.feat[k]; } });
  await put("p:tenant:" + t.id, t); return { ok: true };
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
    const paud = (await list("p:audit:", 300)).sort((a, c) => c.ts - a.ts);
    return { me: { name: me.name, role: "platform" }, reqs, tenants, pset: (await get("p:settings")) || {}, audit: paud };
  }
  const tid = me.tid, sen = SEN.includes(me.role), ps = await pset(), fm = featMap(ps, me.t), plat = !!me.plat, F = (k) => plat || fm[k];
  const [c, menu, orders, bookings, stockAll, staff, aud, sts] = await Promise.all([
    get(tKey(tid, "cfg")), list(tKey(tid, "menu") + ":"), list(tKey(tid, "orders") + ":", 600),
    F("bookings") ? list(tKey(tid, "bookings") + ":", 300) : [], list(tKey(tid, "stock") + ":"), STF.includes(me.role) && F("staff") ? list(tKey(tid, "staff") + ":") : [],
    STF.includes(me.role) && F("audit") ? list(tKey(tid, "audit") + ":", 300) : [], sen && F("stocktake") ? list(tKey(tid, "stocktakes") + ":", 60) : [],
  ]);
  const byName = (a, z) => String(a.name).localeCompare(String(z.name)), qty = {}; stockAll.forEach((s) => (qty[s.id] = s.qty));
  let pkg;
  if (STF.includes(me.role)) pkg = { plan: me.t.plan || "", fee: me.t.fee || 0, period: me.t.period || "month", paidUntil: me.t.paidUntil || 0, pay: ps.pay || "" };
  return {
    me: { name: me.name, role: me.role }, slug: me.t.slug, pkg, plat,
    cfg: { name: (c && c.name) || me.t.name, phone: (c && c.phone) || "", addr: (c && c.addr) || "", tag: (c && c.tag) || "", foot: (c && c.foot) || "", logo: (c && c.logo) || "", lw: (c && c.lw) || 0, lh: (c && c.lh) || 0 },
    feat: plat ? Object.fromEntries(MODS.map((k) => [k, true])) : fm, vat: vatOf(c, ps), depts: await deptsOf(tid, ps),
    menu: menu.map((m) => Object.assign({}, m, { left: m.sku && qty[m.sku] !== undefined ? qty[m.sku] : null })).sort(byName),
    orders: orders.sort((a, z) => z.ts - a.ts),
    bookings,
    stock: (sen ? stockAll : []).sort(byName),
    stocktakes: sts.sort((a, z) => z.ts - a.ts),
    audit: aud.sort((a, z) => z.ts - a.ts),
    at: now(),
    staff: staff.map((s) => ({ id: s.id, name: s.name, role: s.role })).sort(byName),
  };
}

async function aCfg(b, me) {
  need(me, STF);
  const old = (await get(tKey(me.tid, "cfg"))) || {}, c = Object.assign({}, old);
  const pick = (k, n) => { if (b[k] !== undefined) c[k] = str(b[k], n); };
  pick("name", 80); pick("phone", 30); pick("addr", 120); pick("tag", 200); pick("foot", 200);
  if (!c.name) throw bad("Enter the hotel name.");
  if (b.vat !== undefined) { const v = Number(b.vat); if (!isFinite(v) || v < 0 || v > 30) throw bad("VAT must be between 0 and 30."); c.vat = Math.round(v * 100) / 100; }
  if (b.depts !== undefined) { const d = [...new Set((Array.isArray(b.depts) ? b.depts : String(b.depts).split(",")).map((x) => str(x, 20)).filter(Boolean))]; if (!d.length || d.length > 8) throw bad("Enter 1 to 8 sections."); c.depts = d; }
  if (b.logo !== undefined) {
    if (b.logo === "") { delete c.logo; delete c.lw; delete c.lh; }
    else {
      const L = String(b.logo);
      if (!L.startsWith("data:image/jpeg;base64,/9j/") || L.length > 200000 || !/^data:image\/jpeg;base64,[A-Za-z0-9+\/=]+$/.test(L)) throw bad("The logo must be a JPG under 150 KB.");
      c.logo = L; c.lw = Math.min(2000, Math.max(1, Math.round(+b.lw) || 1)); c.lh = Math.min(2000, Math.max(1, Math.round(+b.lh) || 1));
    }
  }
  await put(tKey(me.tid, "cfg"), c);
  await audit(me, "Settings", b.logo !== undefined ? "Logo changed" : "Hotel details changed");
  return { ok: true };
}

async function aAdd(b, me) {
  const c = b.c, it = b.item || {};
  if (c === "stock") {
    need(me, SEN); await needFeat(me, "inventory");
    const name = str(it.name, 80); if (!name) throw bad("Enter an item name.");
    const cost = it.cost === undefined || it.cost === "" ? 0 : Number(it.cost); if (!isFinite(cost) || cost < 0) throw bad("Enter a valid cost.");
    const o = { id: uid(), name, qty: +it.qty || 0, unit: str(it.unit, 20) || "unit", min: +it.min || 0, cost: Math.round(cost * 100) / 100 };
    await put(tKey(me.tid, "stock", o.id), o);
    await audit(me, "Stock added", `${o.name}: ${o.qty} ${o.unit}`); return { ok: true, id: o.id };
  }
  if (c === "menu") {
    need(me, SEN); await needFeat(me, "menu");
    const name = str(it.name, 80), price = +it.price;
    if (!name || !(price > 0)) throw bad("Enter a name and a price.");
    if (!(await deptsOf(me.tid, await pset())).includes(it.dept)) throw bad("Choose a section.");
    let sku = str(it.sku, 40);
    if (sku && !(await get(tKey(me.tid, "stock", sku)))) sku = "";
    const o = { id: uid(), name, price, dept: it.dept, sku };
    await put(tKey(me.tid, "menu", o.id), o);
    await audit(me, "Menu added", `${o.name} KSh ${o.price}`); return { ok: true, id: o.id };
  }
  if (c === "staff") {
    need(me, STF); await needFeat(me, "staff");
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
    await needFeat(me, "bookings");
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
    await put(tKey(me.tid, "staff", id), s); return { ok: true };
  }
  need(me, SEN);
  if (c === "stock") {
    await needFeat(me, "inventory");
    const o = await get(tKey(me.tid, "stock", id)); if (!o) throw bad("Stock item not found.");
    let did = false;
    if (patch.delta !== undefined && patch.delta !== "") {
      const d = +patch.delta; if (!d || !isFinite(d)) throw bad("Enter a number, like 24 or -3.");
      const before = o.qty; o.qty = Math.round((o.qty + d) * 1000) / 1000; did = true;
      await audit(me, d > 0 ? "Stock in" : "Stock out", `${o.name}: ${d > 0 ? "+" : ""}${d} (${before} to ${o.qty} ${o.unit})${patch.why ? " - " + str(patch.why, 80) : ""}`);
    }
    const ed = [];
    if (patch.name !== undefined) { const n = str(patch.name, 80); if (!n) throw bad("Enter an item name."); if (n !== o.name) { ed.push("name"); o.name = n; } }
    if (patch.unit !== undefined) { const u = str(patch.unit, 20) || "unit"; if (u !== o.unit) { ed.push("unit"); o.unit = u; } }
    if (patch.min !== undefined) { const m = Number(patch.min); if (!isFinite(m) || m < 0) throw bad("Enter a valid low-stock level."); if (m !== o.min) { ed.push("low level"); o.min = m; } }
    if (patch.cost !== undefined) { const k = Number(patch.cost); if (!isFinite(k) || k < 0) throw bad("Enter a valid cost."); if (k !== (o.cost || 0)) { ed.push("cost"); o.cost = Math.round(k * 100) / 100; } }
    if (ed.length) { did = true; await audit(me, "Stock edited", `${o.name}: ${ed.join(", ")} changed`); }
    if (!did) throw bad("Nothing to change.");
    await put(tKey(me.tid, "stock", id), o); return { ok: true };
  }
  if (c === "menu") {
    const o = await get(tKey(me.tid, "menu", id)); if (!o) throw bad("Menu item not found.");
    if (patch.name !== undefined) o.name = str(patch.name, 80) || o.name;
    if (patch.price !== undefined && +patch.price > 0) o.price = +patch.price;
    if (patch.dept !== undefined && (await deptsOf(me.tid, await pset())).includes(patch.dept)) o.dept = patch.dept;
    await put(tKey(me.tid, "menu", id), o); await audit(me, "Menu edited", `${o.name} KSh ${o.price}`); return { ok: true };
  }
  throw bad("Unknown item type.");
}

async function aDel(b, me) {
  const c = b.c, id = str(b.id, 40);
  if (!["stock", "menu", "staff"].includes(c)) throw bad("Unknown item type.");
  need(me, c === "staff" ? STF : SEN);
  await needFeat(me, c === "staff" ? "staff" : c === "menu" ? "menu" : "inventory");
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
  const total = Math.round(lines.reduce((a, l) => a + l.p * l.q, 0) * 100) / 100;

  const deltas = lineDeltas(lines, -1);
  if (old) { const back = lineDeltas(old.lines, 1); for (const k in back) deltas[k] = (deltas[k] || 0) + back[k]; }
  await moveStock(tid, deltas);

  let o;
  if (old) o = old;
  else {
    const seq = ((await get(tKey(tid, "seq"))) || { n: 0 }); seq.n++; await put(tKey(tid, "seq"), seq);
    o = { id: cid || uid(), no: seq.n, ts: now(), by: me.name, status: "open" };
    if (b.off) { o.off = true; o.madeTs = Math.min(now(), +b.off || now()); }
  }
  Object.assign(o, { lines, total, name, phone, ref });
  if (pay) Object.assign(o, { status: "paid", pay, paidTs: now(), cashier: me.name });
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

/* ---------- stock take ---------- */
const stK = (tid, id) => tKey(tid, "stocktakes", id);
const stMath = (st) => { const o = { cnt: 0, over: 0, short: 0 }; st.lines.forEach((l) => { if (l.cnt == null) return; o.cnt++; const w = (l.cnt - l.sys) * (l.cost || 0); if (w > 0) o.over += w; else o.short -= w; }); o.over = Math.round(o.over * 100) / 100; o.short = Math.round(o.short * 100) / 100; o.net = Math.round((o.over - o.short) * 100) / 100; return o; };
async function aStNew(b, me) {
  need(me, SEN); await needFeat(me, "stocktake");
  if ((await list(tKey(me.tid, "stocktakes") + ":")).some((x) => x.status === "draft")) throw bad("Finish or cancel the open stock take first.");
  const scope = b.scope === "low" ? "low" : "all", stock = (await list(tKey(me.tid, "stock") + ":")).filter((s) => scope === "all" || s.qty <= s.min).sort((a, z) => String(a.name).localeCompare(String(z.name)));
  if (!stock.length) throw bad("No stock items match. Add stock items first.");
  const seq = (await get(tKey(me.tid, "stseq"))) || { n: 0 }; seq.n++; await put(tKey(me.tid, "stseq"), seq);
  const st = { id: uid(), no: "ST-" + String(seq.n).padStart(4, "0"), ts: now(), by: me.name, status: "draft", scope, blind: !!b.blind, note: str(b.note, 200),
    lines: stock.map((s) => ({ sid: s.id, name: s.name, unit: s.unit, sys: s.qty, cost: s.cost || 0, cnt: null, reason: "", rc: false })) };
  await put(stK(me.tid, st.id), st); await audit(me, "Stock take started", `${st.no} (${st.lines.length} items)`); return { st };
}
async function aStCount(b, me) {
  need(me, SEN); await needFeat(me, "stocktake");
  const st = await get(stK(me.tid, str(b.id, 40))); if (!st) throw bad("Stock take not found.");
  if (st.status !== "draft") throw bad("This stock take was already posted.");
  const counts = b.counts && typeof b.counts === "object" ? b.counts : {}, reasons = b.reasons && typeof b.reasons === "object" ? b.reasons : {}, rc = b.rc && typeof b.rc === "object" ? b.rc : {};
  st.lines.forEach((l) => {
    if (l.sid in counts) { const v = counts[l.sid]; let n = v === null || v === "" ? null : Math.round(Math.max(0, +v) * 1000) / 1000; if (n !== null && !isFinite(n)) n = null; l.cnt = n; if (n === null || n === l.sys) l.reason = ""; }
    if (l.sid in reasons && l.cnt !== null && l.cnt !== l.sys) l.reason = str(reasons[l.sid], 40);
    if (l.sid in rc) l.rc = !!rc[l.sid];
  });
  await put(stK(me.tid, st.id), st); return { st };
}
async function aStPost(b, me) {
  need(me, STF); await needFeat(me, "stocktake");
  const st = await get(stK(me.tid, str(b.id, 40))); if (!st) throw bad("Stock take not found.");
  if (st.status !== "draft") throw bad("This stock take was already posted.");
  const counted = st.lines.filter((l) => l.cnt != null), noReason = counted.filter((l) => l.cnt !== l.sys && !l.reason).length;
  if (!counted.length) throw bad("Count at least one item first.");
  if (noReason) throw bad(noReason + " item(s) have a variance but no reason. Select a reason for each one.");
  let adj = 0;
  for (const l of counted) {
    const s = await get(tKey(me.tid, "stock", l.sid)); if (!s) continue;
    const moved = Math.round((s.qty - l.sys) * 1000) / 1000, after = Math.max(0, Math.round((l.cnt + moved) * 1000) / 1000);
    l.moved = moved; l.after = after; if (after !== s.qty) { s.qty = after; await put(tKey(me.tid, "stock", l.sid), s); adj++; }
  }
  const m = stMath(st); st.status = "posted"; st.posted = { ts: now(), by: me.name, net: m.net, short: m.short, over: m.over, adj };
  await put(stK(me.tid, st.id), st); await audit(me, "Stock take posted", `${st.no}: ${adj} item(s) adjusted, net KSh ${m.net} (short ${m.short}, over ${m.over})`); return { st };
}
async function aStCancel(b, me) {
  need(me, STF); await needFeat(me, "stocktake");
  const st = await get(stK(me.tid, str(b.id, 40))); if (!st) throw bad("Stock take not found.");
  if (st.status !== "draft") throw bad("A posted stock take cannot be deleted.");
  await del(stK(me.tid, st.id)); await audit(me, "Stock take cancelled", st.no); return { ok: true };
}

/* ---------- platform audit trail ---------- */
async function paudit(name, act, detail) {
  try { const id = String(now()).padStart(14, "0") + "-" + uid(); await put("p:audit:" + id, { id, ts: now(), who: name, role: "platform", act, d: str(detail, 300) }); } catch (e) { console.error("paudit", e); }
}
const PLOG = { p_approve: "Request approved", p_reject: "Request rejected", p_create: "Client created", p_status: "Client status", p_reset: "Client password reset", p_plan: "Package edited", p_paid: "Marked paid", p_settings: "Payment details changed", p_defaults: "Defaults changed", p_tfeat: "Client features changed", p_pw: "Password changed", p_profile: "Profile changed" };
async function plog(a, b, me) {
  let who = "";
  if (b.id) { const x = (await get("p:tenant:" + str(b.id, 40))) || (await get("p:req:" + str(b.id, 40))); who = x ? x.name : ""; }
  let act = PLOG[a] || a, d = who;
  if (a === "p_create") d = str(b.name, 80);
  if (a === "p_status") act = b.status === "suspended" ? "Client suspended" : "Client activated";
  if (a === "p_plan" || a === "p_approve") d += `: ${str(b.plan, 40)} KSh ${Number(b.fee) || 0} ${str(b.period, 8)}` + (b.paidUntil ? `, paid until ${str(b.paidUntil, 10)}` : "");
  if (a === "p_defaults") d = [b.vat !== undefined && `VAT ${b.vat}%`, b.depts !== undefined && `sections ${[].concat(b.depts).join(", ")}`, b.feat && "module switches"].filter(Boolean).join("; ");
  if (a === "p_tfeat") d = who + ": " + Object.entries(b.feat || {}).map(([k, v]) => `${k} ${v}`).join(", ");
  if (a === "p_settings") d = "Payment details, contact or site address updated";
  if (a === "p_pw") d = "Own password changed";
  if (a === "p_profile") d = `Name changed to ${str(b.name, 80)}`;
  await paudit(me.name, act, d);
}
async function aPProfile(b, me) {
  const name = str(b.name, 80);
  if (!name) throw bad("Enter your name.");
  const a = me._a; a.name = name; await put("p:admin", a);
  return { ok: true, name };
}
async function aPPw(b, me) {
  if (!checkPw(String(b.cur || ""), me._a.hash)) throw bad("Your current password is wrong.");
  if (String(b.pw || "").length < 8) throw bad("New password must be at least 8 characters.");
  const a = me._a; a.hash = hashPw(String(b.pw)); a.sv = svOf(a) + 1; await put("p:admin", a);
  return { ok: true, t: sign({ r: "platform", e: a.email, sv: svOf(a) }) };
}

/* ---------- router ---------- */
const PUBLIC = { status: aStatus, setup: aSetup, login: aLogin, signup: aSignup, pub: aPub, book: aBook, gorder: aGOrder, ai: aAi };
const PLATFORM = { p_approve: aPApprove, p_reject: aPReject, p_create: aPCreate, p_status: aPStatus, p_reset: aPReset, p_plan: aPPlan, p_paid: aPPaid, p_settings: aPSettings, p_defaults: aPDefaults, p_tfeat: aPTFeat, p_pw: aPPw, p_profile: aPProfile };
const HOTEL = { cfg: aCfg, add: aAdd, upd: aUpd, del: aDel, order: aOrder, void: aVoid, st_new: aStNew, st_count: aStCount, st_post: aStPost, st_cancel: aStCancel };

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
    let out;
    if (a === "sync") out = await aSync(b, me);
    else if (a === "signout_all") {
      if (me.plat) throw bad("Use your own platform sign-in for this.");
      if (me.role === "platform") { me._a.sv = svOf(me._a) + 1; await put("p:admin", me._a); }
      else if (me.role === "owner") { me.t.sv = svOf(me.t) + 1; await put("p:tenant:" + me.t.id, me.t); }
      else { me._s.sv = svOf(me._s) + 1; await put(tKey(me.tid, "staff", me.sid), me._s); }
      out = { ok: true };
    }
    else if (PLATFORM[a]) { if (me.role !== "platform") throw bad("Not allowed."); out = await PLATFORM[a](b, me); await plog(a, b, me); }
    else if (HOTEL[a]) { if (me.role === "platform") throw bad("Not allowed."); out = await HOTEL[a](b, me); }
    else return send(400, { err: "Unknown request." });
    if (me._p && out && typeof out === "object" && now() - (me._p.iat || 0) > 12 * 3600e3) out.nt = sign({ r: me._p.r, e: me._p.e, tid: me._p.tid, sid: me._p.sid, sv: me._p.sv });
    return send(200, out);
  } catch (e) {
    if (e instanceof HttpErr) return send(e.code, { err: e.message });
    console.error(e);
    return send(500, { err: "Server error. Please try again." });
  }
};

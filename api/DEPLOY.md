# DK HBR POS – hotel, bar and restaurant (cloud, multi-client)

Files go in the ROOT of your GitHub repo (keep the `api` folder):
index.html · api/s.js · sw.js · manifest.webmanifest · icon-192.png · icon-512.png · icon-maskable-512.png · vercel.json · supabase.sql

## Set up (once)
1. Supabase > SQL Editor: run supabase.sql (skip if the `kv` table already exists).
2. Vercel > Settings > Environment Variables:
   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY   (the Supabase integration adds these)
   ADMIN_SETUP_CODE   a long secret you choose (used once to create the platform admin)
   SESSION_SECRET     (optional) a long random string
3. Push to GitHub. Vercel redeploys by itself.
4. Open the site > footer > Sign in. The first time, it asks for ADMIN_SETUP_CODE and creates YOUR platform admin
   (name, email, password). Use "Owner or admin" to sign in afterwards.

## How clients work
- The main address (your-site.vercel.app) is the platform page. A hotel owner presses "Request account" and fills in
  hotel, owner, email, phone, location and password.
- You sign in as platform admin > Requests > Approve (or Reject). You can also use "Create client" to make an
  account yourself, for demos or for clients who ask you to do it.
- Clients: suspend or activate an account, and reset an owner's password.
- Each approved hotel gets a Hotel code and a guest booking page: your-site.vercel.app/?h=HOTELCODE
  Guests book there; the hotel sees the bookings in its own Bookings tab.
- The hotel owner signs in with email + password ("Owner or admin"). Staff sign in with Hotel code + name + PIN
  ("Hotel staff"). The owner adds staff under Staff and edits hotel name, phone and address under Settings.
- Every hotel's data is separate (keys t:<hotel id>:*). Clients never see each other's data.

## Sign in (one screen)
- Owner or admin: type your email, then your password.
- Hotel staff: type the Hotel code, then your name, then your PIN. The name box appears by itself.

## Rights inside a hotel
Owner and Director: everything, incl. managers, staff, settings and audit trail.
Manager: runs the staff (adds waiters, reception, cashiers, supervisors; resets PINs; changes roles), settings, audit trail, stock, menu, voids, reports.
Supervisor: stock, menu, voids, reports. Reception: bookings, bills and payment. Cashier: bills and payment. Waiter: bills only.
Audit trail (Manager, Director, Owner): every sale, void, stock change, staff change and sign-in, with who and when. Cannot be edited.
Stock page: add items, stock in/out with a reason, low-stock alerts, movement log. Sales deduct stock by themselves.

## Offline and install
- Works on phones, tablets and computers. Install: Android/Chrome "Install app" button in the top bar, iPhone Safari Share > Add to Home Screen.
- Without internet, staff stay signed in and can still take and pay bills. They are saved on the device (receipt numbers look like OFF3) and sync by themselves when the internet returns. Stock and the audit trail update at that moment.
- Stock, menu and staff changes need internet.

Updating: replace index.html, sw.js and api/s.js on GitHub. Data lives in Supabase and is not touched.

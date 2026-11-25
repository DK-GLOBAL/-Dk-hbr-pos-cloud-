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

## Rights inside a hotel
Owner and manager: everything, incl. staff and settings. Supervisor: inventory, menu, voids, reports.
Cashier: bills and payment. Waiter: bills only. The guest's phone prints on every receipt.

Updating later: replace only index.html and api/s.js on GitHub. Data lives in Supabase and is not touched.
Not included from the spa version: two-step login, email alerts, PDF documents, the AI helper.

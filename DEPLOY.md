# DK HBR POS – hotel, bar and restaurant (cloud version)

Files go in the ROOT of your GitHub repo (keep the `api` folder):
index.html · api/s.js · sw.js · manifest.webmanifest · icon-192.png · icon-512.png · icon-maskable-512.png · vercel.json · supabase.sql

1. Supabase > SQL Editor: run supabase.sql once (skip if the `kv` table already exists).
2. Vercel > Settings > Environment Variables:
   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY   (the Supabase integration adds these)
   ADMIN_SETUP_CODE   a long secret you choose (used once to create the owner)
   SESSION_SECRET     (optional) a long random string
3. Push to GitHub. Vercel redeploys by itself.
4. Open the site > footer > Staff login. The first time it asks for ADMIN_SETUP_CODE and creates the owner.
5. Staff tab: add managers, supervisors, cashiers, waiters (each with their own PIN).
6. Menu and Inventory tabs: add stock, then menu items linked to stock so each sale deducts it.

Edit the hotel name, tagline, phone and address at the top of the script in index.html (const HOTEL).

Rights: owner and manager = everything. Supervisor = inventory, menu, voids, reports. Cashier = bills and payment. Waiter = bills only.
Guest phone numbers entered online or at the till print on every receipt.
Data lives in Supabase (table kv, keys h:*), so updating the files never erases it.

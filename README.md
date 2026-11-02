# JALIYAAN SALES — Netlify version

Private customer order and ledger portal with a white-and-gold theme. This package is prepared for Netlify static hosting plus a Netlify Function backend. It is **not published yet** and will not work until the Supabase database and Netlify environment variables are configured.

## Features in this starter
- Admin and customers sign in with numeric codes only.
- Admin can create customer names and numeric codes (6–12 digits).
- Product catalogue, orders, customer-only order history, and ledger entries persist in Supabase.
- Admin can accept/cancel pending orders; customers see status.
- Customers can delete their own pending order within 5 minutes, if the admin has not handled it.
- Wrong code displays an “Invalid code” message below the input.
- No online payment system is included.
- Optional WhatsApp Cloud API notification hook; it needs separate credentials and setup.

## Required setup before publishing
1. Create a Supabase project and open its SQL Editor.
2. Run the full contents of `sql/schema.sql`.
3. In Netlify, import/upload this project as a site with the included `netlify.toml`; ensure build settings use the `public` folder and `netlify/functions` folder as configured.
4. Add these environment variables in Netlify Site configuration → Environment variables:
   - `SUPABASE_URL` — Supabase project URL
   - `SUPABASE_SERVICE_ROLE_KEY` — Supabase service-role key (secret; never place in browser code)
   - `ADMIN_CODE` — admin numeric code; this package is set up for `583174`
   - `SESSION_SECRET` — long random secret (at least 32 characters)
   - `NODE_ENV` — `production`
5. Install dependencies/build in Netlify. `package.json` includes `serverless-http` for the function adapter.
6. Redeploy after setting environment variables. Test login, add one test product, create a test customer, place an order, and test ledger visibility before using real customer data.

## Security and privacy notes
- The published URL is reachable by anyone who has it; sharing the link privately is not the same as making the site inaccessible to the public. Admin/customer codes protect the app's features.
- The app uses a signed, HTTP-only session cookie so login does not depend on a temporary in-memory session store.
- Keep the Supabase service-role key only in Netlify environment variables. Never share screenshots that reveal it.
- Choose unique customer codes and send them privately. A numeric code is less secure than a strong password or one-time code; avoid easy-to-guess codes.
- The optional WhatsApp notification only works after the Meta WhatsApp Cloud API is configured and tested.
- Verify applicable laws and age restrictions before listing or selling tobacco products.

## Local development (optional)
1. `npm install`
2. Copy `.env.example` to `.env` and fill in valid secrets.
3. `npm start`

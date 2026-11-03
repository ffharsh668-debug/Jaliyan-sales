# JALIYAAN SALES

JALIYAAN SALES is a customer ordering and business-management portal. The frontend is the root-level `index.html`; the Express API runs locally or through the Netlify Function adapter.

## Current features

- Admin and customer access-code login with signed HTTP-only session cookies.
- Product catalogue and customer cart/order placement.
- Admin order review, accept/cancel actions, invoices, print/PDF and WhatsApp text sharing.
- Customer ledger, payments, supplier directory and supplier ledger.
- Purchase drafts, expenses, daily cash book, CSV exports and estimated profit reports.
- Customer inbox, read receipts, customer login history and admin action history.
- English and Gujarati interface translations.
- Android WebView wrapper and GitHub Actions debug APK build.

## Supabase setup

1. Create a Supabase project and open **SQL Editor**.
2. Run the complete contents of `schema.sql`. It is designed to be re-runnable and adds the tables/columns required by the current backend without dropping existing data.
3. Keep the Supabase service-role key secret. It belongs only in server environment variables.

## Netlify setup

This repository includes `netlify.toml`:
- Publish directory: repository root (`.`)
- Functions directory: `netlify/functions`
- API requests under `/api/*` are redirected to the Netlify Function.

Configure these environment variables in Netlify:

- `SUPABASE_URL` — Supabase project URL.
- `SUPABASE_SERVICE_ROLE_KEY` — Supabase service-role key; never put it in browser code.
- `ADMIN_CODE` — private main admin access code.
- `SESSION_SECRET` — long random secret (at least 32 characters).
- `NODE_ENV` — set to `production`.

Optional WhatsApp Cloud API notifications require `ADMIN_WHATSAPP_NUMBER`, `WHATSAPP_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`, and optionally `WHATSAPP_API_VERSION`.

After configuring variables, trigger a new production deploy. Check the deploy log and test admin login, customer login, product loading, a test order, order acceptance, ledger update, payment entry and inbox before using real transactions.

## Local development

1. Install Node.js 18 or newer.
2. Run `npm install`.
3. Set the environment variables listed above (for local use, `NODE_ENV` can be omitted).
4. Run `npm start` and open `http://localhost:3000`.

## Android APK

The GitHub Actions workflow `.github/workflows/android-apk.yml` builds a debug APK on pushes to `main` and on manual runs. Download the `JALIYAAN-SALES-APK` artifact from the completed workflow run.

## Security and accounting notes

- The site URL is public; access codes protect application features but do not make the URL private.
- The service-role key must remain server-side. Do not store credentials or API secrets in Business Settings.
- Customer access codes are hashed in Supabase. Use unique, hard-to-guess codes and share them privately.
- The profit and cash-book reports are operational estimates, not audited accounts or statutory GST-compliant accounting.
- Age confirmation in the interface is not identity verification. Follow all applicable laws and verify customer eligibility independently where required.

-- Run in the Supabase SQL Editor. Never expose the service-role key in browser code.
create extension if not exists pgcrypto;

create table if not exists public.customers (
  id uuid primary key default gen_random_uuid(),
  display_name text not null,
  access_code_hash text not null unique,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text not null default '',
  price numeric(12,2) not null check (price >= 0),
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.customers(id),
  items jsonb not null,
  total numeric(12,2) not null check (total >= 0),
  status text not null default 'pending' check (status in ('pending','accepted','cancelled')),
  editable_until timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.ledger_entries (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.customers(id),
  amount numeric(12,2) not null check (amount <> 0),
  note text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists orders_customer_created_idx on public.orders(customer_id, created_at desc);
create index if not exists ledger_customer_created_idx on public.ledger_entries(customer_id, created_at desc);
create index if not exists customers_active_idx on public.customers(active);

-- Enable RLS; server uses service-role key only. Keep that key secret.
alter table public.customers enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.ledger_entries enable row level security;

-- =========================================================
-- JALIYAAN SALES: COMPLETE BACKEND SCHEMA
-- Safe to re-run. Adds missing columns/tables without deleting data.
-- The backend uses the Supabase service-role key only on the server.
-- =========================================================

-- Extend the original starter tables for all current app features.
ALTER TABLE public.customers
  ADD COLUMN IF NOT EXISTS age_verified boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS last_login_at timestamptz;

ALTER TABLE public.products
  ADD COLUMN IF NOT EXISTS cost_price numeric(12,2) NOT NULL DEFAULT 0 CHECK (cost_price >= 0),
  ADD COLUMN IF NOT EXISTS sku text,
  ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'Tobacco',
  ADD COLUMN IF NOT EXISTS unit text NOT NULL DEFAULT 'piece',
  ADD COLUMN IF NOT EXISTS stock_quantity integer NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0),
  ADD COLUMN IF NOT EXISTS low_stock_threshold integer NOT NULL DEFAULT 0 CHECK (low_stock_threshold >= 0),
  ADD COLUMN IF NOT EXISTS brand text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS pack_size text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS barcode text NOT NULL DEFAULT '';

ALTER TABLE public.orders
  ADD COLUMN IF NOT EXISTS customer_note text NOT NULL DEFAULT '';

-- Additional admin access codes.
CREATE TABLE IF NOT EXISTS public.admin_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name text NOT NULL,
  access_code_hash text NOT NULL UNIQUE,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Supplier directory.
CREATE TABLE IF NOT EXISTS public.suppliers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  contact_person text NOT NULL DEFAULT '',
  phone text NOT NULL DEFAULT '',
  email text NOT NULL DEFAULT '',
  address text NOT NULL DEFAULT '',
  gstin text NOT NULL DEFAULT '',
  notes text NOT NULL DEFAULT '',
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Purchase records and received purchase history.
CREATE TABLE IF NOT EXISTS public.purchases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  supplier_id uuid REFERENCES public.suppliers(id) ON DELETE SET NULL,
  invoice_number text NOT NULL DEFAULT '',
  purchase_date date NOT NULL DEFAULT CURRENT_DATE,
  items jsonb NOT NULL DEFAULT '[]'::jsonb,
  subtotal numeric(12,2) NOT NULL DEFAULT 0 CHECK (subtotal >= 0),
  tax_amount numeric(12,2) NOT NULL DEFAULT 0 CHECK (tax_amount >= 0),
  other_charges numeric(12,2) NOT NULL DEFAULT 0 CHECK (other_charges >= 0),
  total numeric(12,2) NOT NULL DEFAULT 0 CHECK (total >= 0),
  amount_paid numeric(12,2) NOT NULL DEFAULT 0 CHECK (amount_paid >= 0),
  notes text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'draft',
  received_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Inventory movement history used by purchase receiving and admin APIs.
CREATE TABLE IF NOT EXISTS public.inventory_movements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id uuid NOT NULL REFERENCES public.products(id) ON DELETE RESTRICT,
  movement_type text NOT NULL,
  quantity integer NOT NULL CHECK (quantity > 0),
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Business expenses.
CREATE TABLE IF NOT EXISTS public.expenses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  category text NOT NULL,
  description text NOT NULL DEFAULT '',
  amount numeric(12,2) NOT NULL CHECK (amount > 0),
  expense_date date NOT NULL DEFAULT CURRENT_DATE,
  payment_method text NOT NULL DEFAULT 'cash',
  reference_number text NOT NULL DEFAULT '',
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Customer receipts and supplier payments.
CREATE TABLE IF NOT EXISTS public.customer_payments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id uuid NOT NULL REFERENCES public.customers(id) ON DELETE RESTRICT,
  order_id uuid REFERENCES public.orders(id) ON DELETE SET NULL,
  amount numeric(12,2) NOT NULL CHECK (amount > 0),
  payment_method text NOT NULL DEFAULT 'cash',
  reference_number text NOT NULL DEFAULT '',
  notes text NOT NULL DEFAULT '',
  payment_date date NOT NULL DEFAULT CURRENT_DATE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.supplier_payments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  supplier_id uuid NOT NULL REFERENCES public.suppliers(id) ON DELETE RESTRICT,
  purchase_id uuid REFERENCES public.purchases(id) ON DELETE SET NULL,
  amount numeric(12,2) NOT NULL CHECK (amount > 0),
  payment_method text NOT NULL DEFAULT 'cash',
  reference_number text NOT NULL DEFAULT '',
  notes text NOT NULL DEFAULT '',
  payment_date date NOT NULL DEFAULT CURRENT_DATE,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Supplier ledger: positive values are credits, negative values are debits.
CREATE TABLE IF NOT EXISTS public.supplier_ledger_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  supplier_id uuid NOT NULL REFERENCES public.suppliers(id) ON DELETE CASCADE,
  amount numeric(12,2) NOT NULL CHECK (amount <> 0),
  note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Inbox messages and per-customer read receipts.
CREATE TABLE IF NOT EXISTS public.inbox_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  message_type text NOT NULL CHECK (message_type IN ('group','personal')),
  recipient_customer_id uuid REFERENCES public.customers(id) ON DELETE CASCADE,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (message_type = 'group' AND recipient_customer_id IS NULL) OR
    (message_type = 'personal' AND recipient_customer_id IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS public.inbox_reads (
  message_id uuid NOT NULL REFERENCES public.inbox_messages(id) ON DELETE CASCADE,
  customer_id uuid NOT NULL REFERENCES public.customers(id) ON DELETE CASCADE,
  read_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, customer_id)
);

-- Admin audit trail.
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_role text NOT NULL DEFAULT 'admin',
  actor_id uuid,
  actor_name text NOT NULL DEFAULT 'Admin',
  action text NOT NULL,
  entity_type text NOT NULL,
  entity_id text NOT NULL DEFAULT '',
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Flexible business settings (never store passwords or API secrets here).
CREATE TABLE IF NOT EXISTS public.business_settings (
  setting_key text PRIMARY KEY,
  setting_value jsonb NOT NULL DEFAULT 'null'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Indexes for common list/filter operations.
CREATE INDEX IF NOT EXISTS orders_customer_created_idx ON public.orders(customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ledger_customer_created_idx ON public.ledger_entries(customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS customers_active_idx ON public.customers(active);
CREATE INDEX IF NOT EXISTS products_active_name_idx ON public.products(active, name);
CREATE INDEX IF NOT EXISTS suppliers_active_name_idx ON public.suppliers(active, name);
CREATE INDEX IF NOT EXISTS purchases_date_idx ON public.purchases(purchase_date DESC);
CREATE INDEX IF NOT EXISTS expenses_date_idx ON public.expenses(expense_date DESC);
CREATE INDEX IF NOT EXISTS customer_payments_date_idx ON public.customer_payments(payment_date DESC);
CREATE INDEX IF NOT EXISTS supplier_payments_date_idx ON public.supplier_payments(payment_date DESC);
CREATE INDEX IF NOT EXISTS supplier_ledger_supplier_created_idx ON public.supplier_ledger_entries(supplier_id, created_at DESC);
CREATE INDEX IF NOT EXISTS inbox_messages_created_idx ON public.inbox_messages(created_at DESC);
CREATE INDEX IF NOT EXISTS inbox_reads_customer_idx ON public.inbox_reads(customer_id, read_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON public.audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS inventory_movements_product_created_idx ON public.inventory_movements(product_id, created_at DESC);

-- Keep row-level security enabled on every application table.
ALTER TABLE public.admin_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.suppliers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.purchases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_movements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.expenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.customer_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.supplier_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.supplier_ledger_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inbox_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inbox_reads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.business_settings ENABLE ROW LEVEL SECURITY;

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

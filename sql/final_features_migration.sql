-- JALIYAAN SALES final touches migration
-- Run this entire file once in Supabase SQL Editor.
ALTER TABLE public.orders ADD COLUMN IF NOT EXISTS customer_note text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS public.supplier_ledger_entries (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), supplier_id uuid NOT NULL REFERENCES public.suppliers(id) ON DELETE CASCADE, amount numeric(12,2) NOT NULL CHECK (amount <> 0), note text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS supplier_ledger_supplier_created_idx ON public.supplier_ledger_entries(supplier_id, created_at DESC);
ALTER TABLE public.supplier_ledger_entries ENABLE ROW LEVEL SECURITY;

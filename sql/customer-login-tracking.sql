-- Run this once in Supabase SQL Editor to enable Customer Login Check.
ALTER TABLE public.customers
ADD COLUMN IF NOT EXISTS last_login_at timestamptz;

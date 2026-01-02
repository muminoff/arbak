-- Disable FORCE ROW LEVEL SECURITY to allow SECURITY DEFINER functions to bypass RLS
-- This is needed because the helper functions (is_document_owner, has_document_access)
-- need to query these tables without triggering RLS policies (which would cause infinite recursion)
-- Regular users still have RLS enforced; only the table owner can bypass it

ALTER TABLE documents NO FORCE ROW LEVEL SECURITY;
ALTER TABLE document_access NO FORCE ROW LEVEL SECURITY;

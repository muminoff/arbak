-- Fix RLS recursion by disabling row security in helper functions
-- SECURITY DEFINER alone doesn't bypass RLS - we need SET row_security = off

-- Recreate helper function to check document ownership (truly bypasses RLS)
CREATE OR REPLACE FUNCTION is_document_owner(doc_id UUID) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = doc_id AND d.owner_id = current_user_id()
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public SET row_security = off;

-- Recreate helper function to check document access (truly bypasses RLS)
CREATE OR REPLACE FUNCTION has_document_access(doc_id UUID) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM document_access da
        WHERE da.document_id = doc_id
          AND da.user_id = current_user_id()
          AND da.can_read = true
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public SET row_security = off;

-- Fix RLS infinite recursion between documents and document_access

-- Drop existing policies
DROP POLICY IF EXISTS documents_select ON documents;
DROP POLICY IF EXISTS document_access_select ON document_access;

-- Create helper function to check document ownership (bypasses RLS)
CREATE OR REPLACE FUNCTION is_document_owner(doc_id UUID) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = doc_id AND d.owner_id = current_user_id()
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Create helper function to check document access (bypasses RLS)
CREATE OR REPLACE FUNCTION has_document_access(doc_id UUID) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM document_access da
        WHERE da.document_id = doc_id
          AND da.user_id = current_user_id()
          AND da.can_read = true
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Recreate documents_select policy using helper functions
CREATE POLICY documents_select ON documents FOR SELECT USING (
    owner_id = current_user_id()
    OR is_public = true
    OR has_document_access(id)
    OR user_has_permission('document', 'read')
);

-- Recreate document_access_select without referencing documents directly
CREATE POLICY document_access_select ON document_access FOR SELECT USING (
    user_id = current_user_id()
    OR is_document_owner(document_id)
);

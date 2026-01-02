-- Fix document RLS policy to not grant blanket read access
-- The 'document:read' permission should not bypass RLS for all documents
-- Only admins with 'document:manage' permission can read all documents

-- Drop the existing policies first
DROP POLICY IF EXISTS documents_select ON documents;

-- Recreate documents_select policy:
-- Users can read documents if:
-- 1. They own the document
-- 2. The document is public
-- 3. They have explicit access via document_access
-- 4. They have 'manage' permission (admin-level access)
CREATE POLICY documents_select ON documents FOR SELECT USING (
    owner_id = current_user_id()
    OR is_public = true
    OR has_document_access(id)
    OR user_has_permission('document', 'manage')
);

-- Also update the other policies to use 'manage' for admin bypass:

DROP POLICY IF EXISTS documents_update ON documents;
CREATE POLICY documents_update ON documents FOR UPDATE USING (
    owner_id = current_user_id()
    OR EXISTS (
        SELECT 1 FROM document_access da
        WHERE da.document_id = id
          AND da.user_id = current_user_id()
          AND da.can_write = true
    )
    OR user_has_permission('document', 'manage')
);

DROP POLICY IF EXISTS documents_delete ON documents;
CREATE POLICY documents_delete ON documents FOR DELETE USING (
    owner_id = current_user_id()
    OR user_has_permission('document', 'manage')
);

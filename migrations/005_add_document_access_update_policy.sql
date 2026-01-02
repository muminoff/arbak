-- Add UPDATE policy for document_access table
-- This allows document owners to update sharing permissions

CREATE POLICY document_access_update ON document_access FOR UPDATE USING (
    EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = document_id AND d.owner_id = current_user_id()
    )
);

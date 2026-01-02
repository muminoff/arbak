-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enum types
CREATE TYPE permission_action AS ENUM ('create', 'read', 'update', 'delete', 'manage');

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Permissions table
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource_type VARCHAR(100) NOT NULL,
    action permission_action NOT NULL,
    description TEXT,
    UNIQUE(resource_type, action)
);

-- Role-Permission junction
CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- User-Role junction
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- Documents table (example RLS-protected resource)
CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    content TEXT,
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    is_public BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Document access grants
CREATE TABLE document_access (
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    can_read BOOLEAN DEFAULT true,
    can_write BOOLEAN DEFAULT false,
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (document_id, user_id)
);

-- Indexes
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_documents_owner_id ON documents(owner_id);
CREATE INDEX idx_document_access_user_id ON document_access(user_id);
CREATE INDEX idx_document_access_document_id ON document_access(document_id);

-- Helper function to get current user ID from session
CREATE OR REPLACE FUNCTION current_user_id() RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_user_id', true), '')::UUID;
EXCEPTION
    WHEN OTHERS THEN RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Helper function to check if current user has a specific permission
CREATE OR REPLACE FUNCTION user_has_permission(
    p_resource_type VARCHAR,
    p_action permission_action
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON ur.role_id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = current_user_id()
          AND p.resource_type = p_resource_type
          AND (p.action = p_action OR p.action = 'manage')
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Enable RLS on documents
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- RLS Policies for documents
CREATE POLICY documents_select ON documents FOR SELECT USING (
    owner_id = current_user_id()
    OR is_public = true
    OR EXISTS (
        SELECT 1 FROM document_access da
        WHERE da.document_id = id
          AND da.user_id = current_user_id()
          AND da.can_read = true
    )
    OR user_has_permission('document', 'read')
);

CREATE POLICY documents_insert ON documents FOR INSERT WITH CHECK (
    owner_id = current_user_id()
    AND user_has_permission('document', 'create')
);

CREATE POLICY documents_update ON documents FOR UPDATE USING (
    owner_id = current_user_id()
    OR EXISTS (
        SELECT 1 FROM document_access da
        WHERE da.document_id = id
          AND da.user_id = current_user_id()
          AND da.can_write = true
    )
    OR user_has_permission('document', 'update')
);

CREATE POLICY documents_delete ON documents FOR DELETE USING (
    owner_id = current_user_id()
    OR user_has_permission('document', 'delete')
);

-- Enable RLS on document_access
ALTER TABLE document_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_access FORCE ROW LEVEL SECURITY;

CREATE POLICY document_access_select ON document_access FOR SELECT USING (
    user_id = current_user_id()
    OR EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = document_id AND d.owner_id = current_user_id()
    )
);

CREATE POLICY document_access_insert ON document_access FOR INSERT WITH CHECK (
    EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = document_id AND d.owner_id = current_user_id()
    )
);

CREATE POLICY document_access_delete ON document_access FOR DELETE USING (
    EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = document_id AND d.owner_id = current_user_id()
    )
);

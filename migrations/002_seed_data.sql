-- Default roles
INSERT INTO roles (id, name, description) VALUES
    ('00000000-0000-0000-0000-000000000001', 'admin', 'Full system access'),
    ('00000000-0000-0000-0000-000000000002', 'user', 'Standard user access'),
    ('00000000-0000-0000-0000-000000000003', 'viewer', 'Read-only access')
ON CONFLICT (id) DO NOTHING;

-- Default permissions
INSERT INTO permissions (resource_type, action, description) VALUES
    ('document', 'create', 'Create new documents'),
    ('document', 'read', 'Read any document'),
    ('document', 'update', 'Update any document'),
    ('document', 'delete', 'Delete any document'),
    ('document', 'manage', 'Full document access'),
    ('user', 'create', 'Create new users'),
    ('user', 'read', 'View user profiles'),
    ('user', 'update', 'Update user profiles'),
    ('user', 'delete', 'Delete users'),
    ('user', 'manage', 'Full user access')
ON CONFLICT (resource_type, action) DO NOTHING;

-- Admin gets 'manage' on everything
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id FROM permissions WHERE action = 'manage'
ON CONFLICT DO NOTHING;

-- User gets create, read, update on documents
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource_type = 'document' AND action IN ('create', 'read', 'update')
ON CONFLICT DO NOTHING;

-- Viewer gets read on documents
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource_type = 'document' AND action = 'read'
ON CONFLICT DO NOTHING;

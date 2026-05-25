CREATE TABLE IF NOT EXISTS broker_secrets (
    id BIGSERIAL PRIMARY KEY,
    system TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'read',
    encrypted_secret TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(system, resource_type, resource_id, action)
);

CREATE TABLE IF NOT EXISTS broker_leases (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    system TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'read',
    lease_status TEXT NOT NULL DEFAULT 'active',
    expires_at TIMESTAMPTZ NOT NULL,
    granted_by TEXT NOT NULL DEFAULT 'operator',
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS broker_audit_log (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    details JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_broker_leases_lookup
    ON broker_leases(agent_id, system, resource_type, action, lease_status, expires_at);
CREATE INDEX IF NOT EXISTS idx_broker_audit_created
    ON broker_audit_log(created_at DESC);

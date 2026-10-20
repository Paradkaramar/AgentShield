-- backend/app/db/postgres_schema.sql
-- AgentShield Continuous Network Monitoring & Asset Discovery
-- Production PostgreSQL Enterprise Schema Definition
-- Compatible with PostgreSQL 13+ with strict integrity, indexing, and cascade rules.

BEGIN;

-- 1. Approved Network Scan Scopes
CREATE TABLE IF NOT EXISTS approved_scan_scopes (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    cidr_or_ip CIDR NOT NULL,
    is_approved SMALLINT NOT NULL DEFAULT 1,
    organization_id VARCHAR(64) NOT NULL DEFAULT 'org-default',
    asset_tag VARCHAR(120) NOT NULL DEFAULT 'Internal Infrastructure',
    created_by VARCHAR(64) NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_scopes_cidr ON approved_scan_scopes USING gist (cidr_or_ip inet_ops);
CREATE INDEX IF NOT EXISTS idx_scan_scopes_approved ON approved_scan_scopes (is_approved);

-- 2. Sensitive Network Asset Exclusions
CREATE TABLE IF NOT EXISTS network_exclusions (
    id BIGSERIAL PRIMARY KEY,
    scope_id BIGINT REFERENCES approved_scan_scopes(id) ON DELETE SET NULL,
    ip_address INET NOT NULL UNIQUE,
    reason VARCHAR(255) NOT NULL,
    created_by VARCHAR(64) NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_network_exclusions_ip ON network_exclusions USING gist (ip_address inet_ops);

-- 3. Monitoring Configuration & State
CREATE TABLE IF NOT EXISTS network_monitoring_config (
    id BIGSERIAL PRIMARY KEY,
    service_enabled SMALLINT NOT NULL DEFAULT 1,
    is_paused SMALLINT NOT NULL DEFAULT 0,
    emergency_stop SMALLINT NOT NULL DEFAULT 0,
    scan_interval_seconds INTEGER NOT NULL DEFAULT 60 CHECK (scan_interval_seconds >= 10),
    scan_duration_limit_seconds INTEGER NOT NULL DEFAULT 120 CHECK (scan_duration_limit_seconds >= 10),
    max_concurrency INTEGER NOT NULL DEFAULT 10 CHECK (max_concurrency BETWEEN 1 AND 50),
    probe_timeout_seconds NUMERIC(4, 2) NOT NULL DEFAULT 1.00 CHECK (probe_timeout_seconds > 0),
    target_ports_json JSONB NOT NULL DEFAULT '[21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8000, 8080]'::jsonb,
    last_scan_at TIMESTAMPTZ,
    next_scan_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Scan Jobs & Execution Runs
CREATE TABLE IF NOT EXISTS scan_jobs (
    id VARCHAR(64) PRIMARY KEY,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'PAUSED')),
    triggered_by VARCHAR(64) NOT NULL DEFAULT 'SCHEDULER',
    target_scope_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    hosts_scanned INTEGER NOT NULL DEFAULT 0,
    hosts_up INTEGER NOT NULL DEFAULT 0,
    ports_found INTEGER NOT NULL DEFAULT 0,
    changes_detected INTEGER NOT NULL DEFAULT 0,
    alerts_generated INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs (status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_started_at ON scan_jobs (started_at DESC);

-- 5. Network Assets Inventory (Baseline & Discovered)
CREATE TABLE IF NOT EXISTS network_assets (
    id VARCHAR(64) PRIMARY KEY,
    ip_address INET UNIQUE NOT NULL,
    hostname VARCHAR(255),
    mac_address MACADDR,
    status VARCHAR(32) NOT NULL DEFAULT 'REACHABLE' CHECK (status IN ('REACHABLE', 'OFFLINE', 'UNKNOWN')),
    in_baseline SMALLINT NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scan_job_id VARCHAR(64) REFERENCES scan_jobs(id) ON DELETE SET NULL,
    latency_ms NUMERIC(7, 2),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_network_assets_ip ON network_assets USING gist (ip_address inet_ops);
CREATE INDEX IF NOT EXISTS idx_network_assets_baseline ON network_assets (in_baseline);
CREATE INDEX IF NOT EXISTS idx_network_assets_status ON network_assets (status);

-- 6. Service Observations
CREATE TABLE IF NOT EXISTS service_observations (
    id BIGSERIAL PRIMARY KEY,
    asset_id VARCHAR(64) REFERENCES network_assets(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol VARCHAR(16) NOT NULL DEFAULT 'tcp',
    service_name VARCHAR(64) NOT NULL,
    banner VARCHAR(255),
    state VARCHAR(32) NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'CLOSED', 'FILTERED')),
    is_baseline SMALLINT NOT NULL DEFAULT 0,
    first_observed TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_observed TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scan_job_id VARCHAR(64) REFERENCES scan_jobs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_service_obs_ip_port ON service_observations (ip_address, port);
CREATE INDEX IF NOT EXISTS idx_service_obs_baseline ON service_observations (is_baseline);

-- 7. Network Security Alerts
CREATE TABLE IF NOT EXISTS network_security_alerts (
    id BIGSERIAL PRIMARY KEY,
    scan_job_id VARCHAR(64) REFERENCES scan_jobs(id) ON DELETE SET NULL,
    alert_type VARCHAR(64) NOT NULL CHECK (alert_type IN ('NEW_HOST_DISCOVERED', 'UNEXPECTED_OPEN_PORT', 'CHANGED_SERVICE', 'PORT_CLOSED', 'CRITICAL_PORT_EXPOSED', 'HOST_OFFLINE', 'SCOPE_VIOLATION_BLOCKED')),
    severity VARCHAR(32) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    title VARCHAR(255) NOT NULL,
    observed_fact TEXT NOT NULL,
    suspected_threat TEXT NOT NULL,
    target_ip INET NOT NULL,
    target_port INTEGER CHECK (target_port IS NULL OR (target_port BETWEEN 1 AND 65535)),
    evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_network_alerts_status ON network_security_alerts (status);
CREATE INDEX IF NOT EXISTS idx_network_alerts_severity ON network_security_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_network_alerts_created_at ON network_security_alerts (created_at DESC);

-- 8. Seed Baseline Scopes & Configuration
INSERT INTO network_monitoring_config (
    service_enabled, is_paused, emergency_stop, scan_interval_seconds,
    scan_duration_limit_seconds, max_concurrency, probe_timeout_seconds,
    target_ports_json, updated_at
) VALUES (
    1, 0, 0, 60, 120, 10, 1.00,
    '[21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8000, 8080]'::jsonb,
    CURRENT_TIMESTAMP
) ON CONFLICT DO NOTHING;

INSERT INTO approved_scan_scopes (name, cidr_or_ip, is_approved, asset_tag, created_by)
VALUES
    ('Loopback Control Plane', '127.0.0.1/32'::cidr, 1, 'Local Enclave', 'admin'),
    ('Enterprise AI Subnet', '192.168.1.0/24'::cidr, 1, 'Agent Nodes', 'admin')
ON CONFLICT DO NOTHING;

INSERT INTO network_exclusions (ip_address, reason, created_by)
VALUES
    ('192.168.1.1'::inet, 'Core Gateway Router — Excluded to prevent edge disruption', 'admin')
ON CONFLICT DO NOTHING;

COMMIT;

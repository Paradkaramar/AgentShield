-- backend/app/db/postgres_endpoint_schema.sql
-- AgentShield Installable Personal Device Security Platform
-- Production PostgreSQL Enterprise Schema & Security Configuration
-- Compatible with PostgreSQL 13+ with strict integrity, indexing, and cascade rules.

BEGIN;

-- ============================================================================
-- 1. ENROLLED DEVICES
-- ============================================================================
CREATE TABLE IF NOT EXISTS enrolled_devices (
    id VARCHAR(64) PRIMARY KEY,
    device_name VARCHAR(120) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(32) NOT NULL CHECK (os_type IN ('windows', 'linux', 'darwin')),
    os_release VARCHAR(64) NOT NULL,
    os_version VARCHAR(64) NOT NULL,
    agent_version VARCHAR(32) NOT NULL DEFAULT '1.2.0',
    device_token_hash CHAR(64) NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    monitoring_status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (monitoring_status IN ('ACTIVE', 'PAUSED', 'DISCONNECTED', 'REVOKED')),
    is_revoked SMALLINT NOT NULL DEFAULT 0,
    revocation_reason TEXT,
    ip_address INET,
    mac_address MACADDR,
    cpu_cores INTEGER NOT NULL DEFAULT 4,
    total_memory_mb INTEGER NOT NULL DEFAULT 8192
);

CREATE INDEX IF NOT EXISTS idx_enrolled_devices_status ON enrolled_devices (monitoring_status);
CREATE INDEX IF NOT EXISTS idx_enrolled_devices_token_hash ON enrolled_devices (device_token_hash);
CREATE INDEX IF NOT EXISTS idx_enrolled_devices_revoked ON enrolled_devices (is_revoked);
CREATE INDEX IF NOT EXISTS idx_enrolled_devices_last_heartbeat ON enrolled_devices (last_heartbeat DESC);

-- ============================================================================
-- 2. GRANULAR PERMISSION & CONSENT RECORDS
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_consent_records (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES enrolled_devices(id) ON DELETE CASCADE,
    permission_key VARCHAR(64) NOT NULL,
    display_name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    is_mandatory SMALLINT NOT NULL DEFAULT 0,
    granted SMALLINT NOT NULL DEFAULT 1,
    requires_admin SMALLINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    consent_signature VARCHAR(128),
    CONSTRAINT uq_device_permission UNIQUE (device_id, permission_key)
);

CREATE INDEX IF NOT EXISTS idx_device_consent_device ON device_consent_records (device_id);
CREATE INDEX IF NOT EXISTS idx_device_consent_granted ON device_consent_records (device_id, granted);

-- ============================================================================
-- 3. DEVICE HEALTH & AGENT RUNTIME TELEMETRY
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_health_telemetry (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES enrolled_devices(id) ON DELETE CASCADE,
    cpu_percent NUMERIC(5, 2) NOT NULL,
    memory_percent NUMERIC(5, 2) NOT NULL,
    memory_used_mb INTEGER NOT NULL,
    disk_percent NUMERIC(5, 2) NOT NULL,
    agent_uptime_seconds INTEGER NOT NULL,
    active_modules_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_health_device_time ON device_health_telemetry (device_id, timestamp DESC);

-- ============================================================================
-- 4. PROCESS METADATA INVENTORY
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_processes (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES enrolled_devices(id) ON DELETE CASCADE,
    pid INTEGER NOT NULL,
    name VARCHAR(120) NOT NULL,
    username VARCHAR(120),
    exe_path TEXT,
    cmdline TEXT,
    cpu_percent NUMERIC(5, 2) NOT NULL DEFAULT 0.0,
    memory_mb NUMERIC(8, 2) NOT NULL DEFAULT 0.0,
    is_suspicious SMALLINT NOT NULL DEFAULT 0,
    suspicious_reason TEXT,
    fact_classification VARCHAR(32) NOT NULL DEFAULT 'observed_fact' CHECK (fact_classification IN ('observed_fact', 'heuristic_flag', 'confirmed_threat')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_processes_device ON device_processes (device_id);
CREATE INDEX IF NOT EXISTS idx_device_processes_suspicious ON device_processes (device_id, is_suspicious);

-- ============================================================================
-- 5. NETWORK CONNECTIONS TELEMETRY
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_connections (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES enrolled_devices(id) ON DELETE CASCADE,
    local_ip INET NOT NULL,
    local_port INTEGER NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
    remote_ip INET,
    remote_port INTEGER CHECK (remote_port IS NULL OR (remote_port BETWEEN 1 AND 65535)),
    protocol VARCHAR(16) NOT NULL DEFAULT 'tcp',
    status VARCHAR(32) NOT NULL,
    pid INTEGER,
    process_name VARCHAR(120),
    is_suspicious SMALLINT NOT NULL DEFAULT 0,
    suspicious_reason TEXT,
    fact_classification VARCHAR(32) NOT NULL DEFAULT 'observed_fact' CHECK (fact_classification IN ('observed_fact', 'heuristic_flag', 'confirmed_threat')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_conn_device ON device_connections (device_id);
CREATE INDEX IF NOT EXISTS idx_device_conn_suspicious ON device_connections (device_id, is_suspicious);

-- ============================================================================
-- 6. LISTENING PORTS & SERVICES
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_listening_ports (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES enrolled_devices(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol VARCHAR(16) NOT NULL DEFAULT 'tcp',
    bind_address VARCHAR(64) NOT NULL,
    pid INTEGER,
    service_name VARCHAR(120),
    is_unexpected SMALLINT NOT NULL DEFAULT 0,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_ports_device ON device_listening_ports (device_id, port);

-- ============================================================================
-- 7. HOST FIREWALL STATUS
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_firewall_status (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL UNIQUE REFERENCES enrolled_devices(id) ON DELETE CASCADE,
    os_firewall_type VARCHAR(32) NOT NULL CHECK (os_firewall_type IN ('windows_defender', 'ufw', 'nftables')),
    is_enabled SMALLINT NOT NULL DEFAULT 1,
    profile_statuses_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    default_inbound VARCHAR(16) NOT NULL DEFAULT 'BLOCK',
    default_outbound VARCHAR(16) NOT NULL DEFAULT 'ALLOW',
    active_rules_count INTEGER NOT NULL DEFAULT 0,
    last_inspected TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    raw_summary TEXT
);

-- ============================================================================
-- 8. ENDPOINT SECURITY ALERTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_security_alerts (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES enrolled_devices(id) ON DELETE CASCADE,
    severity VARCHAR(32) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    category VARCHAR(64) NOT NULL CHECK (category IN ('SUSPICIOUS_PROCESS', 'UNUSUAL_CONNECTION', 'FIREWALL_CHANGE', 'UNEXPECTED_LISTENING_PORT', 'FILE_HEURISTIC', 'AGENT_HEARTBEAT_LOSS')),
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    classification VARCHAR(32) NOT NULL DEFAULT 'heuristic_flag' CHECK (classification IN ('observed_fact', 'heuristic_flag', 'confirmed_threat')),
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    suggested_action TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_alerts_device ON device_security_alerts (device_id);
CREATE INDEX IF NOT EXISTS idx_device_alerts_status ON device_security_alerts (status);
CREATE INDEX IF NOT EXISTS idx_device_alerts_severity ON device_security_alerts (severity);

-- ============================================================================
-- 9. ENROLLMENT TOKENS
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_enrollment_tokens (
    token VARCHAR(64) PRIMARY KEY,
    created_by VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used SMALLINT NOT NULL DEFAULT 0,
    used_by_device_id VARCHAR(64) REFERENCES enrolled_devices(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_valid ON device_enrollment_tokens (expires_at, used);

-- ============================================================================
-- 10. AUDIT LOGS FOR ENDPOINT OPERATIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES enrolled_devices(id) ON DELETE CASCADE,
    action VARCHAR(64) NOT NULL,
    actor VARCHAR(64) NOT NULL,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_audit_device ON device_audit_logs (device_id, timestamp DESC);

-- ============================================================================
-- LEAST-PRIVILEGE ROLE SETUP GUIDE
-- ============================================================================
-- Execute the following in production PostgreSQL:
--
-- CREATE ROLE agentshield_app WITH LOGIN PASSWORD 'strong_application_password_here';
-- CREATE ROLE agentshield_agent WITH LOGIN PASSWORD 'strong_agent_ingest_password_here';
--
-- GRANT CONNECT ON DATABASE agentshield TO agentshield_app, agentshield_agent;
-- GRANT USAGE ON SCHEMA public TO agentshield_app, agentshield_agent;
--
-- -- Application Role has full management rights on endpoint tables:
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agentshield_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agentshield_app;
--
-- -- Agent Role is strictly restricted to inserting telemetry, updating heartbeat, and reading its own consent:
-- GRANT INSERT ON device_health_telemetry, device_processes, device_connections, device_listening_ports, device_security_alerts, device_audit_logs TO agentshield_agent;
-- GRANT UPDATE (last_heartbeat, monitoring_status) ON enrolled_devices TO agentshield_agent;
-- GRANT SELECT (id, monitoring_status, is_revoked) ON enrolled_devices TO agentshield_agent;
-- GRANT SELECT ON device_consent_records TO agentshield_agent;
-- GRANT USAGE, SELECT ON SEQUENCE device_health_telemetry_id_seq, device_processes_id_seq, device_connections_id_seq, device_listening_ports_id_seq, device_security_alerts_id_seq, device_audit_logs_id_seq TO agentshield_agent;

COMMIT;

-- ============================================================================
-- SecureAccess Pro - Database schema
-- Zero Trust Network Access Control System
-- ----------------------------------------------------------------------------
-- The Flask backend creates these tables automatically via SQLAlchemy
-- (db.create_all()). This file documents the schema and can be used to
-- provision a PostgreSQL database manually.
-- ============================================================================

-- Users + roles (RBAC) ------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50)  UNIQUE NOT NULL,
    email           VARCHAR(120) UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,          -- bcrypt hash
    role            VARCHAR(20)  NOT NULL DEFAULT 'Viewer',  -- Admin | User | Viewer
    totp_secret     VARCHAR(64)  NOT NULL,          -- base32 TOTP shared secret
    failed_attempts INTEGER      NOT NULL DEFAULT 0, -- brute-force counter
    locked_until    TIMESTAMP,                       -- account lockout expiry
    created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- Access / audit log (resource access decisions) ----------------------------
CREATE TABLE IF NOT EXISTS access_logs (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50),
    action      VARCHAR(50),        -- LOGIN | ACCESS | REGISTER | MANAGE_ROLE ...
    resource    VARCHAR(100),       -- HR Portal | Finance Dashboard | ...
    status      VARCHAR(20),        -- SUCCESS | GRANTED | DENIED | FAILED | LOCKED
    ip_address  VARCHAR(64),
    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Login history (authentication attempts) -----------------------------------
CREATE TABLE IF NOT EXISTS login_history (
    id             SERIAL PRIMARY KEY,
    username       VARCHAR(50),
    login_time     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address     VARCHAR(64),
    status         VARCHAR(20),      -- SUCCESS | FAILED
    failure_reason VARCHAR(120)
);

-- Site access (raw request tracking - Zero Trust "verify everything") --------
CREATE TABLE IF NOT EXISTS site_access (
    id            SERIAL PRIMARY KEY,
    ip_address    VARCHAR(64),
    method        VARCHAR(10),
    page_accessed VARCHAR(200),
    access_time   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_agent    VARCHAR(300),
    status        VARCHAR(20)
);

-- Helpful indexes for the real-time dashboard queries -----------------------
CREATE INDEX IF NOT EXISTS idx_access_logs_ts    ON access_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_login_history_ts  ON login_history (login_time DESC);
CREATE INDEX IF NOT EXISTS idx_site_access_ts    ON site_access (access_time DESC);

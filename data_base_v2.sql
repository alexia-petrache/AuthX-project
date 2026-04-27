-- ============================================================
-- AuthX DB Schema v2 (SECURIZATA)
-- ============================================================

DROP TABLE IF EXISTS reset_tokens CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS tickets CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(20) CHECK (role IN ('ANALYST', 'MANAGER')) NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locked        BOOLEAN DEFAULT FALSE,
    login_attempts INT DEFAULT 0,
    locked_until  TIMESTAMP
);

CREATE TABLE tickets (
    id          SERIAL PRIMARY KEY,
    title       VARCHAR(255) NOT NULL,
    description TEXT,
    severity    VARCHAR(10) CHECK (severity IN ('LOW', 'MED', 'HIGH')) NOT NULL,
    status      VARCHAR(20) CHECK (status IN ('OPEN', 'IN PROGRESS', 'RESOLVED')) NOT NULL DEFAULT 'OPEN',
    owner_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_logs (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(50) NOT NULL,
    resource    VARCHAR(50),
    resource_id VARCHAR(50),
    ip_address  VARCHAR(45),
    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE reset_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    expires_at  TIMESTAMP NOT NULL,
    used        BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Utilizatori demo cu parole hash-uite cu bcrypt (cost 12)
-- admin@authx.com     -> Admin@2024!
-- analyst@authx.com   -> Analyst@2024!
INSERT INTO users (email, password_hash, role) VALUES
    ('admin@authx.com',   '$2b$12$52necz4xbJhjWmC8M0jXGeJHz.IJnKMlW8lgHyTuzpIpuY1Nd/DVu', 'MANAGER'),
    ('analyst@authx.com', '$2b$12$5Y.ll/pQ3iWx15teBNIrcOWHjZIhsyRVSprJspkIEI8GvhRdGjmD2', 'ANALYST');

INSERT INTO tickets (title, description, severity, status, owner_id) VALUES
    ('Scurgere date HR',    'Date personale angajati expuse in API public.', 'HIGH', 'OPEN', 1),
    ('Parola admin slaba',  'Contul de admin foloseste parola slaba.', 'HIGH', 'OPEN', 1),
    ('Log-uri incomplete',  'Sistemul de audit nu logheaza toate actiunile.', 'MED', 'IN PROGRESS', 2);

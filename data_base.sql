DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS tickets CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role        VARCHAR(20) CHECK (role IN ('ANALYST', 'MANAGER')) NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locked      BOOLEAN DEFAULT FALSE
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

INSERT INTO users (email, password_hash, role) VALUES
    ('admin@authx.com',   '123',           'MANAGER'),
    ('analyst@authx.com', 'parola123',     'ANALYST'),
    ('test@authx.com',    'test',          'ANALYST');

INSERT INTO tickets (title, description, severity, status, owner_id) VALUES
    ('Scurgere date HR', 'Date personale angajati expuse in API public.', 'HIGH', 'OPEN', 1),
    ('Parola admin slaba', 'Contul de admin foloseste parola "123".', 'HIGH', 'OPEN', 1),
    ('Log-uri incomplete', 'Sistemul de audit nu logheaza toate actiunile.', 'MED', 'IN PROGRESS', 2);

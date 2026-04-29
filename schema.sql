PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'ANALYST'
                    CHECK (role IN ('ANALYST', 'MANAGER')),
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked          INTEGER NOT NULL DEFAULT 0

);

CREATE TABLE IF NOT EXISTS tickets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    description TEXT,
    severity    TEXT    NOT NULL DEFAULT 'LOW'
                CHECK (severity IN ('LOW', 'MED', 'HIGH')),
    status      TEXT    NOT NULL DEFAULT 'OPEN'
                CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED')),
    owner_id    INTEGER NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    action      TEXT    NOT NULL,
    resource    TEXT,
    resource_id TEXT,
    timestamp   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address  TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

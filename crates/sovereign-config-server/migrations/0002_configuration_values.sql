CREATE TABLE configuration_values (
    path TEXT COLLATE "C" PRIMARY KEY
        CHECK (path ~ '^[a-z0-9-]+(/[a-z0-9-]+)*$'),
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= created_at)
);

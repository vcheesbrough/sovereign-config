CREATE TABLE schema_metadata (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_metadata (id) VALUES (1);

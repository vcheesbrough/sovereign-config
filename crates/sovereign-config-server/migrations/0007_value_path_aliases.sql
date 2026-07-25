-- Split stored value content from its access paths so a single value can be
-- exposed at multiple canonical paths (card #243). Content lives in
-- configuration_value_contents; each configuration_paths row is one canonical
-- alias referencing a content by id. Deleting a path removes only that alias;
-- content is cleaned up in the same transaction once its last path is gone.

CREATE TABLE configuration_value_contents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    value TEXT NOT NULL,
    classification TEXT NOT NULL
        CHECK (classification IN ('plain', 'secret')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= created_at)
);

CREATE TABLE configuration_paths (
    path TEXT COLLATE "C" PRIMARY KEY
        CHECK (path ~ '^/[a-z0-9-]+(/[a-z0-9-]+)*$'),
    content_id BIGINT NOT NULL
        REFERENCES configuration_value_contents (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= created_at)
);

CREATE INDEX configuration_paths_content_id_idx
    ON configuration_paths (content_id);

-- Migrate the existing strict 1:1 rows: each becomes one content row plus one
-- path row. A transient column correlates each new content row back to its
-- originating path; it is dropped once the path rows are inserted.
ALTER TABLE configuration_value_contents ADD COLUMN migration_path TEXT;

INSERT INTO configuration_value_contents (value, classification, created_at, updated_at, migration_path)
SELECT value, classification, created_at, updated_at, path
FROM configuration_values;

INSERT INTO configuration_paths (path, content_id, created_at, updated_at)
SELECT migration_path, id, created_at, updated_at
FROM configuration_value_contents;

ALTER TABLE configuration_value_contents DROP COLUMN migration_path;

DROP TABLE configuration_values;

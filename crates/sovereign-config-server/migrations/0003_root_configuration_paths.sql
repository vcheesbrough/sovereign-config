DELETE FROM configuration_values;

ALTER TABLE configuration_values
    DROP CONSTRAINT configuration_values_path_check;

ALTER TABLE configuration_values
    ADD CONSTRAINT configuration_values_rooted_path_check
    CHECK (path ~ '^/[a-z0-9-]+(/[a-z0-9-]+)*$');

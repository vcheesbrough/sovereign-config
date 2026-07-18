ALTER TABLE configuration_values
    ADD COLUMN classification TEXT NOT NULL DEFAULT 'plain';

ALTER TABLE configuration_values
    ADD CONSTRAINT configuration_values_classification_check
    CHECK (classification IN ('plain', 'secret'));

ALTER TABLE configuration_values
    ALTER COLUMN classification DROP DEFAULT;

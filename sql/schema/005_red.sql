-- +goose Up
ALTER TABLE users
    ADD COLUMN is_chirpy_red BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE users
    DROP COLUMN IF EXISTS is_chirpy_red CASCADE;

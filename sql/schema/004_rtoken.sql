-- +goose Up
CREATE TABLE refresh_tokens (
    token TEXT NOT NULL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id)
                            ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    revoked_AT TIMESTAMP
);

-- +goose Down
DROP TABLE refresh_tokens;

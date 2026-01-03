-- name: CreateUser :one
INSERT INTO users ( id, created_at, updated_at, email, hashed_password )
VALUES ( gen_random_uuid(), now(), now(), $1, $2 )
RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: UpdateUserDataByID :exec
UPDATE users
SET email = $2,
    hashed_password = $3,
    updated_at = now()
WHERE id = $1;

-- name: UpgradeUserByID :exec
UPDATE users
SET is_chirpy_red = TRUE
WHERE id = $1;

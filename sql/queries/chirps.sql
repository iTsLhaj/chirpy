-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES ( gen_random_uuid(), now(), now(), $1, $2 )
RETURNING *;

-- name: GetAllChirps :many
SELECT * FROM chirps
ORDER BY
    CASE WHEN $1 IS TRUE THEN created_at END ASC,
    CASE WHEN $1 IS FALSE THEN created_at END DESC;

-- name: GetAllChirpsByUID :many
SELECT * FROM chirps
WHERE user_id = $1
ORDER BY
    CASE WHEN $2 IS TRUE THEN created_at END ASC,
    CASE WHEN $2 IS FALSE THEN created_at END DESC;

-- name: DeleteAllChirps :exec
DELETE FROM chirps;

-- name: GetChirpByID :one
SELECT * FROM chirps
WHERE id = $1;

-- name: DeleteChirpByID :exec
DELETE FROM chirps
WHERE id = $1;

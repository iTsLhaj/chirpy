package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func extractKey(headers http.Header, prefix string) (string, error) {
	token, ok := strings.CutPrefix(headers.Get("Authorization"), prefix)
	if !ok {
		return "", errors.New(fmt.Sprintf("no %s token found", prefix))
	}
	return strings.Trim(token, "\r\n "), nil
}

func HashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func CheckPasswordHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: "chirpy",
		IssuedAt: &jwt.NumericDate{
			Time: time.Now().UTC(),
		},
		ExpiresAt: &jwt.NumericDate{
			Time: time.Now().Add(expiresIn).UTC(),
		},
		Subject: userID.String(),
	})
	t, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return t, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	if !token.Valid {
		return uuid.Nil, fmt.Errorf("Token Invalid")
	}

	var uuidString string
	uuidString, err = token.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}

	var userID uuid.UUID
	userID, err = uuid.Parse(uuidString)
	if err != nil {
		return uuid.Nil, err
	}

	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	return extractKey(headers, "Bearer ")
}

func MakeRefreshToken() (string, error) {
	var b []byte = make([]byte, 32)
	rand.Read(b)

	return hex.EncodeToString(b), nil
}

func GetAPIKey(headers http.Header) (string, error) {
	return extractKey(headers, "ApiKey ")
}

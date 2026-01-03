package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/iTsLhaj/chirpy/internal/auth"
	"github.com/iTsLhaj/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
)

type apiConfig struct {
	fileServerHits atomic.Int32
	dbQuery        *database.Queries
	platform       string
	jwtSecret      string
	polkaSecret    string
}

type polkaEvent string

const (
	USER_UPGRADE polkaEvent = "user.upgraded"
)

type errResp struct {
	Error string `json:"error"`
}

func (apic *apiConfig) verifyRefreshToken(ctx context.Context, h http.Header) (bool, database.RefreshToken) {
	token, err := auth.GetBearerToken(h)
	if err != nil {
		return false, database.RefreshToken{}
	}

	var dbRtoken database.RefreshToken
	dbRtoken, err = apic.dbQuery.GetRefreshToken(ctx, token)
	if err != nil {
		return false, database.RefreshToken{}
	}

	if time.Now().After(dbRtoken.ExpiresAt) || dbRtoken.RevokedAt.Valid {
		return false, database.RefreshToken{}
	}

	return true, dbRtoken
}

func (apic *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apic.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (apic *apiConfig) middlewareRouteProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apic.platform != "dev" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (apic *apiConfig) middlewareAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		_, err = auth.ValidateJWT(token, apic.jwtSecret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (apic *apiConfig) middlewareRTAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (apic *apiConfig) fetchFileServerHits() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Kahya 1.0")
		w.WriteHeader(http.StatusOK)

		t := `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`
		responseBody := fmt.Sprintf(t, apic.fileServerHits.Load())
		_, err := w.Write([]byte(responseBody))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}

func (apic *apiConfig) resetFileServerHits() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := apic.dbQuery.DeleteAllUsers(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = apic.dbQuery.DeleteAllChirps(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		apic.fileServerHits.And(0)
		w.Header().Set("Server", "Kahya 1.0")
		w.WriteHeader(http.StatusOK)
	})
}

func (apic *apiConfig) handleChirpValidation() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type reqJSON struct {
			Body string `json:"body"`
		}
		type validResp struct {
			CleanedBody string `json:"cleaned_body"`
		}
		var reqPostData reqJSON

		raw, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		err = json.Unmarshal(raw, &reqPostData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		if len(reqPostData.Body) > 140 {
			w.WriteHeader(http.StatusBadRequest)
			data, _ := json.Marshal(errResp{"Chirp is too long"})
			w.Write(data)
			return
		}

		var cleaned []byte = []byte(reqPostData.Body)
		re, _ := regexp.Compile(`(?i)\bFornax|Kerfuffle|Sharbert\b`)
		cleaned = re.ReplaceAll([]byte(cleaned), []byte("****"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		data, _ := json.Marshal(validResp{CleanedBody: string(cleaned)})
		w.Write(data)
	})
}

func (apic *apiConfig) handleUserCreation() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type reqJSON struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		type User struct {
			Id          uuid.UUID `json:"id"`
			CreatedAt   time.Time `json:"created_at"`
			UpdatedAt   time.Time `json:"updated_at"`
			Email       string    `json:"email"`
			IsChirpyRed bool      `json:"is_chirpy_red"`
		}

		var reqPostData reqJSON
		var raw []byte
		var err error
		raw, err = ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		err = json.Unmarshal(raw, &reqPostData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		email := reqPostData.Email
		var hpassword string
		hpassword, err = auth.HashPassword(reqPostData.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var dbUser database.User
		dbUser, err = apic.dbQuery.CreateUser(r.Context(), database.CreateUserParams{
			Email:          email,
			HashedPassword: hpassword,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var user User
		user.Id = dbUser.ID
		user.CreatedAt = dbUser.CreatedAt
		user.UpdatedAt = dbUser.UpdatedAt
		user.Email = dbUser.Email
		user.IsChirpyRed = dbUser.IsChirpyRed
		var respBody []byte
		respBody, err = json.Marshal(user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(respBody)
	})
}

func (apic *apiConfig) handleChirps() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type reqJSON struct {
			Body   string `json:"body"`
			UserId string
		}
		type resChirp struct {
			Id        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		rbody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err.Error())
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var reqPostData reqJSON
		err = json.Unmarshal(rbody, &reqPostData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err.Error())
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		token, _ := auth.GetBearerToken(r.Header)
		uid, _ := auth.ValidateJWT(token, apic.jwtSecret)
		reqPostData.UserId = uid.String()

		var parsedUID uuid.UUID
		parsedUID, err = uuid.Parse(reqPostData.UserId)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err.Error())
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		if len(reqPostData.Body) > 140 {
			w.WriteHeader(http.StatusBadRequest)
			data, _ := json.Marshal(errResp{"Chirp is too long"})
			w.Write(data)
			return
		}

		var cleaned []byte = []byte(reqPostData.Body)
		re, _ := regexp.Compile(`(?i)\bFornax|Kerfuffle|Sharbert\b`)
		cleaned = re.ReplaceAll([]byte(cleaned), []byte("****"))

		var dbUser database.User
		dbUser, err = apic.dbQuery.GetUserByID(r.Context(), parsedUID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err.Error())
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var chirp database.Chirp
		chirp, err = apic.dbQuery.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   string(cleaned),
			UserID: dbUser.ID,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err.Error())
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var respChirp resChirp
		respChirp.Id = chirp.ID
		respChirp.CreatedAt = chirp.CreatedAt
		respChirp.UpdatedAt = chirp.UpdatedAt
		respChirp.Body = chirp.Body
		respChirp.UserID = chirp.UserID

		w.WriteHeader(http.StatusCreated)
		data, _ := json.Marshal(respChirp)
		w.Write(data)
		return
	})
}

func (apic *apiConfig) getChirps() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type resChirp struct {
			Id        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		sort := true
		sortQueryParam := r.URL.Query().Get("sort")
		if sortQueryParam == "desc" {
			sort = false
		}

		var err error
		var uid uuid.UUID
		var user database.User
		authorIDParam := r.URL.Query().Get("author_id")
		if authorIDParam != "" {
			uid, err = uuid.Parse(authorIDParam)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				data, _ := json.Marshal(errResp{"Something went wrong"})
				w.Write(data)
				return
			}
			user, err = apic.dbQuery.GetUserByID(r.Context(), uid)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				data, _ := json.Marshal(errResp{"Something went wrong"})
				w.Write(data)
				return
			}
		}

		var chirps []database.Chirp
		if authorIDParam != "" {
			chirps, err = apic.dbQuery.GetAllChirpsByUID(r.Context(), database.GetAllChirpsByUIDParams{
				UserID:  user.ID,
				Column2: sort,
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				data, _ := json.Marshal(errResp{"Something went wrong"})
				w.Write(data)
				return
			}
		} else {
			chirps, err = apic.dbQuery.GetAllChirps(r.Context(), sort)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				data, _ := json.Marshal(errResp{"Something went wrong"})
				w.Write(data)
				return
			}
		}

		var respChirps []resChirp
		for _, chirp := range chirps {
			respChirps = append(respChirps, resChirp{
				Id:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID,
			})
		}

		var respBody []byte
		respBody, err = json.Marshal(respChirps)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBody)
	})
}

func (apic *apiConfig) getChirpById() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type resChirp struct {
			Id        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		chirpIDParam := r.PathValue("chirpID")
		chirpID, err := uuid.Parse(chirpIDParam)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var chirp database.Chirp
		chirp, err = apic.dbQuery.GetChirpByID(r.Context(), chirpID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var respBody []byte
		respBody, err = json.Marshal(resChirp{
			Id:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBody)
	})
}

func (apic *apiConfig) handleUserLogin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type reqJSON struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}
		type resJSON struct {
			Id           uuid.UUID `json:"id"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			Email        string    `json:"email"`
			Token        string    `json:"token"`
			RefreshToken string    `json:"refresh_token"`
			IsChirpyRed  bool      `json:"is_chirpy_red"`
		}

		var req reqJSON
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var user database.User
		user, err = apic.dbQuery.GetUserByEmail(r.Context(), req.Email)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var ok bool
		ok, err = auth.CheckPasswordHash(req.Password, user.HashedPassword)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var token string
		token, err = auth.MakeJWT(user.ID, apic.jwtSecret, time.Hour)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var refToken string
		refToken, err = auth.MakeRefreshToken()
		_, err = apic.dbQuery.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refToken,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(time.Hour * 1440),
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var res = resJSON{
			Id:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refToken,
			IsChirpyRed:  user.IsChirpyRed,
		}
		err = json.NewEncoder(w).Encode(&res)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}
	})
}

func (apic *apiConfig) handleRefreshToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type resJSON struct {
			Token string `json:"token"`
		}

		ok, dbRToken := apic.verifyRefreshToken(r.Context(), r.Header)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		accessToken, err := auth.MakeJWT(dbRToken.UserID, apic.jwtSecret, time.Hour)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

		json.NewEncoder(w).Encode(resJSON{
			Token: accessToken,
		})
	})
}

func (apic *apiConfig) handleTokenRevoke() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, dbRToken := apic.verifyRefreshToken(r.Context(), r.Header)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		apic.dbQuery.RevokeToken(r.Context(), dbRToken.Token)
		w.WriteHeader(http.StatusNoContent)
	})
}

func (apic *apiConfig) handleUserUpdate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type reqJSON struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		type resJSON struct {
			Id           uuid.UUID `json:"id"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			Email        string    `json:"email"`
			IsChirpyRead bool      `json:"is_chirpy_read"`
		}

		var req reqJSON
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var user database.User
		token, _ := auth.GetBearerToken(r.Header)
		uid, _ := auth.ValidateJWT(token, apic.jwtSecret)
		user, err = apic.dbQuery.GetUserByID(r.Context(), uid)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var hpwd string
		hpwd, err = auth.HashPassword(req.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		err = apic.dbQuery.UpdateUserDataByID(
			r.Context(),
			database.UpdateUserDataByIDParams{
				ID:             user.ID,
				Email:          req.Email,
				HashedPassword: hpwd,
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		user, err = apic.dbQuery.GetUserByID(r.Context(), uid)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		json.NewEncoder(w).Encode(resJSON{
			Id:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			IsChirpyRead: user.IsChirpyRed,
		})
	})
}

func (apic *apiConfig) handleDeleteChirp() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := auth.GetBearerToken(r.Header)
		uid, _ := auth.ValidateJWT(token, apic.jwtSecret)
		chirpIDParam := r.PathValue("chirpID")
		chirpID, err := uuid.Parse(chirpIDParam)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		var chirp database.Chirp
		chirp, err = apic.dbQuery.GetChirpByID(r.Context(), chirpID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		if chirp.UserID != uid {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		err = apic.dbQuery.DeleteChirpByID(r.Context(), chirp.ID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

func (apic *apiConfig) handlePolkaWebhook() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type polkaData struct {
			UserId string `json:"user_id"`
		}

		type reqJSON struct {
			Event polkaEvent `json:"event"`
			Data  polkaData  `json:"data"`
		}

		key, err := auth.GetAPIKey(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if key != apic.polkaSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var req reqJSON
		err = json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
			return
		}

		if req.Event != USER_UPGRADE {
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			var uid uuid.UUID
			uid, err = uuid.Parse(req.Data.UserId)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				data, _ := json.Marshal(errResp{"Something went wrong"})
				w.Write(data)
				return
			}
			err = apic.dbQuery.UpgradeUserByID(r.Context(), uid)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}

	})
}

func loadDotEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	loadDotEnv()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)

	var sm *http.ServeMux = http.NewServeMux()
	var server http.Server = http.Server{
		Addr:    ":8080",
		Handler: sm,
	}
	var apic apiConfig = apiConfig{
		dbQuery:     dbQueries,
		platform:    os.Getenv("PLATFORM"),
		jwtSecret:   os.Getenv("JWT_SECRET"),
		polkaSecret: os.Getenv("POLKA_KEY"),
	}

	sm.Handle("/app/", apic.middlewareMetricsInc(
		http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	sm.Handle("/app/assets", http.FileServer(http.Dir("./assets")))

	sm.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Server", "Kahya 1.0")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	sm.Handle("POST /api/validate_chirp", apic.handleChirpValidation())
	sm.Handle("POST /api/users", apic.handleUserCreation())
	sm.Handle("POST /api/chirps", apic.middlewareAuthentication(apic.handleChirps()))
	sm.Handle("GET /api/chirps", apic.getChirps())
	sm.Handle("GET /api/chirps/{chirpID}", apic.getChirpById())
	sm.Handle("POST /api/login", apic.handleUserLogin())
	sm.Handle("POST /api/refresh", apic.middlewareRTAuthentication(apic.handleRefreshToken()))
	sm.Handle("POST /api/revoke", apic.middlewareRTAuthentication(apic.handleTokenRevoke()))
	sm.Handle("PUT /api/users", apic.middlewareAuthentication(apic.handleUserUpdate()))
	sm.Handle("DELETE /api/chirps/{chirpID}", apic.middlewareAuthentication(apic.handleDeleteChirp()))
	sm.Handle("POST /api/polka/webhooks", apic.handlePolkaWebhook())

	sm.Handle("GET /admin/metrics", apic.middlewareRouteProtection(apic.fetchFileServerHits()))
	sm.Handle("POST /admin/reset", apic.middlewareRouteProtection(apic.resetFileServerHits()))

	fmt.Printf("Listening on port %s\n", server.Addr)
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

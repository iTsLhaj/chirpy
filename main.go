package main

import (
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
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
		type errResp struct {
			Error string `json:"error"`
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
			Email string `json:"email"`
		}
		type errResp struct {
			Error string `json:"error"`
		}
		type User struct {
			Id        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Email     string    `json:"email"`
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
		var dbUser database.User
		dbUser, err = apic.dbQuery.CreateUser(r.Context(), email)
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
			UserId string `json:"user_id"`
		}

		type errResp struct {
			Error string `json:"error"`
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
		type errResp struct {
			Error string `json:"error"`
		}

		type resChirp struct {
			Id        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		chirps, err := apic.dbQuery.GetAllChirps(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(errResp{"Something went wrong"})
			w.Write(data)
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
		type errResp struct {
			Error string `json:"error"`
		}

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
		dbQuery:  dbQueries,
		platform: os.Getenv("PLATFORM"),
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
	sm.Handle("POST /api/chirps", apic.handleChirps())
	sm.Handle("GET /api/chirps", apic.getChirps())
	sm.Handle("GET /api/chirps/{chirpID}", apic.getChirpById())

	sm.Handle("GET /admin/metrics", apic.middlewareRouteProtection(apic.fetchFileServerHits()))
	sm.Handle("POST /admin/reset", apic.middlewareRouteProtection(apic.resetFileServerHits()))

	fmt.Printf("Listening on port %s\n", server.Addr)
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

package main

import (
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
}

func (apic *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apic.fileServerHits.Add(1)
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
		apic.fileServerHits.And(0)
		w.Header().Set("Server", "Kahya 1.0")
		w.WriteHeader(http.StatusOK)
	})
}

func handleChirpValidation(w http.ResponseWriter, r *http.Request) {
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
}

func main() {
	var sm *http.ServeMux = http.NewServeMux()
	var server http.Server = http.Server{
		Addr:    ":8080",
		Handler: sm,
	}
	var apic apiConfig = apiConfig{}

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
	sm.HandleFunc("POST /api/validate_chirp", handleChirpValidation)

	sm.Handle("GET /admin/metrics", apic.fetchFileServerHits())
	sm.Handle("POST /admin/reset", apic.resetFileServerHits())

	fmt.Printf("Listening on port %s\n", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

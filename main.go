package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// User structure
type User struct {
	ID       int    `json:"id"`
	Role     string `json:"role"`
	Username string `json:"username"`
}

// Memcached configuration
var mc = memcache.New(os.Getenv("MEMCACHED_HOST"))

// Secret key for signing JWTs
var jwtKey = []byte(os.Getenv("JWT_SECRET"))

// Generates a JWT and stores it in Memcached
func generateJWT(user User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":       user.ID,
		"role":     user.Role,
		"username": user.Username,
		"exp":      expirationTime.Unix(),
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	// Store token in Memcached
	err = mc.Set(&memcache.Item{Key: user.Username, Value: []byte(tokenString), Expiration: int32(expirationTime.Unix() - time.Now().Unix())})
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Verifies a JWT
func verifyJWT(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
}

// Fetch user data from the appropriate service
func fetchUserData(username string, isDoctor bool) (map[string]string, error) {
	var userServiceURL string
	if isDoctor {
		userServiceURL = os.Getenv("DOCTOR_SERVICE_URL") + "/read-doctor/doctors/username/" + username
	} else {
		userServiceURL = os.Getenv("USER_SERVICE_URL") + "/read-patient/patients/username/" + username
	}

	resp, err := http.Get(userServiceURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user not found")
	}
	defer resp.Body.Close()

	var userData map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return nil, fmt.Errorf("error processing server response")
	}

	return userData, nil
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsDoctor bool   `json:"isDoctor"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "invalid input data", http.StatusBadRequest)
		return
	}

	userData, err := fetchUserData(creds.Username, creds.IsDoctor)
	if err != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	// Verify password with the verification service
	verifyServiceURL := os.Getenv("VERIFY_SERVICE_URL")
	verifyData := map[string]string{
		"password": creds.Password,
		"hash":     userData["passwordHash"],
	}
	verifyJSON, _ := json.Marshal(verifyData)
	resp, err := http.Post(fmt.Sprintf("%s/verify", verifyServiceURL), "application/json", bytes.NewBuffer(verifyJSON))
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "authentication error", http.StatusUnauthorized)
		return
	}
	defer resp.Body.Close()

	var verifyResponse struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&verifyResponse); err != nil || !verifyResponse.Valid {
		http.Error(w, "incorrect password", http.StatusUnauthorized)
		return
	}

	role := "patient"
	if creds.IsDoctor {
		role = "doctor"
	}

	id, err := strconv.Atoi(userData["id"])
	if err != nil {
		http.Error(w, "invalid user ID format", http.StatusInternalServerError)
		return
	}

	user := User{ID: id, Role: role, Username: userData["username"]}
	token, err := generateJWT(user)
	if err != nil {
		http.Error(w, "error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"token": "%s"}`, token)))
}

// Verify token in Memcached
func verifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "token required", http.StatusUnauthorized)
		return
	}

	_, err := verifyJWT(tokenString)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Health check handler
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/verify-token", verifyTokenHandler).Methods("GET")
	http.HandleFunc("/healthz", HealthCheck)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

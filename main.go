package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsDoctor bool   `json:"isDoctor"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid input data", http.StatusBadRequest)
		return
	}

	// Fetch user from the user service
	userServiceURL := os.Getenv("USER_SERVICE_URL")
	resp, err := http.Get(fmt.Sprintf("%s/read-patient/patients/username/%s", userServiceURL, creds.Username))
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	defer resp.Body.Close()

	var userData struct {
		ID           int    `json:"id"`
		Username     string `json:"username"`
		PasswordHash string `json:"passwordHash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		http.Error(w, "Error processing server response", http.StatusInternalServerError)
		return
	}

	// Verify password with the verification service
	verifyServiceURL := os.Getenv("VERIFY_SERVICE_URL")
	verifyData := map[string]string{
		"password": creds.Password,
		"hash":     userData.PasswordHash,
	}
	verifyJSON, _ := json.Marshal(verifyData)
	resp, err = http.Post(fmt.Sprintf("%s/verify", verifyServiceURL), "application/json", bytes.NewBuffer(verifyJSON))
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Authentication error", http.StatusUnauthorized)
		return
	}
	defer resp.Body.Close()

	var verifyResponse struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&verifyResponse); err != nil || !verifyResponse.Valid {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	// Determine role
	role := "patient"
	if creds.IsDoctor {
		role = "doctor"
	}

	// Generate JWT
	user := User{ID: userData.ID, Role: role, Username: userData.Username}
	token, err := generateJWT(user)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
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
		http.Error(w, "Token required", http.StatusUnauthorized)
		return
	}

	_, err := verifyJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/verify-token", verifyTokenHandler).Methods("GET")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

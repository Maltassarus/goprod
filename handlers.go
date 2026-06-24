package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateRegisterRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	exists, err := UserExistsByEmail(req.Email)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if exists {
		sendErrorResponse(w, "User with this email already exists", http.StatusConflict)
		return
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	user, err := CreateUser(req.Email, req.Username, passwordHash)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		if strings.Contains(err.Error(), "duplicate key") {
			sendErrorResponse(w, "Username or email already exists", http.StatusConflict)
			return
		}
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := AuthResponse{
		Token: token,
		User:  *user,
	}
	sendJSONResponse(w, response, http.StatusCreated)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateLoginRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if !CheckPassword(req.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := AuthResponse{
		Token: token,
		User:  *user,
	}
	sendJSONResponse(w, response, http.StatusOK)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserIDFromContext(r)
	if !ok {
		sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user by ID: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		sendErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	sendJSONResponse(w, user, http.StatusOK)
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	json.NewEncoder(w).Encode(response)
}

func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	return decoder.Decode(v)
}

func validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	if err := ValidateEmail(req.Email); err != nil {
		return err
	}
	if err := ValidatePassword(req.Password); err != nil {
		return err
	}
	if len(req.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	if len(req.Username) > 30 {
		return fmt.Errorf("username must be less than 30 characters")
	}

	return nil
}

func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

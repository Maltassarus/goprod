package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	InitAuth()

	if err := InitDB(); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer CloseDB()

	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/profile", AuthMiddleware(ProfileHandler))
	http.HandleFunc("/health", HealthHandler)

	port := getEnv("SERVER_PORT", "8080")
	log.Printf("Server starting on port %s", port)
	log.Printf("Register: POST http://localhost:%s/register", port)
	log.Printf("Login: POST http://localhost:%s/login", port)
	log.Printf("Profile: GET http://localhost:%s/profile (requires token)", port)
	log.Printf("Health: GET http://localhost:%s/health", port)

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

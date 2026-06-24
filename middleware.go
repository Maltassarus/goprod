package main

import (
	"context"
	"net/http"
	"strings"
)

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendErrorResponse(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			sendErrorResponse(w, "Invalid authorization header format. Use: Bearer <token>", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		claims, err := ValidateToken(tokenString)
		if err != nil {
			sendErrorResponse(w, "Invalid or expired token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "email", claims.Email)
		ctx = context.WithValue(ctx, "username", claims.Username)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func GetUserIDFromContext(r *http.Request) (int, bool) {
	userID, ok := r.Context().Value("userID").(int)
	return userID, ok
}

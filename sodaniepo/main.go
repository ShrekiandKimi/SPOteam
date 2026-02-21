package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

type Claims struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	UserName string `json:"user_name"`
	jwt.RegisteredClaims
}

type User struct {
	ID, Email, Password, Role, Name string
}

type LoginRequest struct {
	Email, Password string
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
	Role    string `json:"role,omitempty"`
}

var jwtSecret = []byte("change-this-secret-key-in-production-2026!")

var users = []User{
	{ID: "admin1", Email: "admin@tracking-system.com", Password: "admin123", Role: "admin", Name: "Иван Петров"},
	{ID: "worker1", Email: "worker@tracking-system.com", Password: "worker123", Role: "worker", Name: "Алекс Петров"},
}

func main() {
	r := mux.NewRouter()

	// 🔹 Статические файлы из Authorization (главная страница)
	r.PathPrefix("/auto.html").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "Authorization/auto.html")
	})
	r.PathPrefix("/script.js").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "Authorization/script.js")
	})
	r.PathPrefix("/styles.css").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "Authorization/styles.css")
	})

	// 🔹 Страницы после авторизации
	r.PathPrefix("/admin.html").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "Admin/admin.html")
	})
	r.PathPrefix("/worker.html").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "workerpage/worker.html")
	})

	// 🔹 API маршруты
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/validate-token", validateTokenHandler).Methods("POST", "OPTIONS")

	// 🔹 CORS
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// 🔹 Главная страница → auto.html
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auto.html", http.StatusTemporaryRedirect)
	})

	fmt.Println("🚀 Сервер: http://localhost:8080")
	fmt.Println("🔑 Admin: admin@tracking-system.com / admin123")
	fmt.Println("🔑 Worker: worker@tracking-system.com / worker123")

	http.ListenAndServe(":8080", r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req LoginRequest
	json.NewDecoder(r.Body).Decode(&req)

	for _, user := range users {
		if user.Email == req.Email && user.Password == req.Password {
			claims := Claims{
				UserID: user.ID, Email: user.Email, Role: user.Role, UserName: user.Name,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, _ := token.SignedString(jwtSecret)
			json.NewEncoder(w).Encode(LoginResponse{Success: true, Token: tokenString, Role: user.Role})
			return
		}
	}
	json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Неверный email или пароль"})
}

func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"valid": true, "role": claims.Role, "name": claims.UserName})
}
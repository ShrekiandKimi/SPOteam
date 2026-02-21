package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

type Claims struct {
	jwt.RegisteredClaims
	UserID   int    `json:"userId"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	UserName string `json:"name"`
}

type User struct {
	ID       int
	Email    string
	Password string  // 🔹 Это поле нужно добавить!
	Role     string
	Name     string
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success     bool   `json:"success"`
	AccessToken string `json:"accessToken,omitempty"`
	Message     string `json:"message,omitempty"`
	Role        string `json:"role,omitempty"`
}

var (
	jwtSecret = []byte("secret-key-2026!")
	db        *sql.DB
)

func initDB() error {
	// 🔹 ЗАМЕНИ password= НА СВОЙ ПАРОЛЬ ОТ POSTGRES!
	connStr := "host=localhost port=5432 user=postgres password=1488 dbname=staff_tracking sslmode=disable"
	
	fmt.Println("🔌 Подключение к PostgreSQL...")
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("ошибка sql.Open: %v", err)
	}

	if err = db.Ping(); err != nil {
		return fmt.Errorf("ошибка db.Ping: %v", err)
	}

	fmt.Println("✅ PostgreSQL подключен!")
	return nil
}

func getUserByEmail(email string) (*User, error) {
	user := &User{}
	// 🔹 ИСПРАВЛЕНО: password_hash вместо password
	err := db.QueryRow(
		"SELECT id, email, password_hash, role, name FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Email, &user.Password, &user.Role, &user.Name)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func generateToken(user User) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID:   user.ID,
		Email:    user.Email,
		Role:     user.Role,
		UserName: user.Name,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func main() {
	// Подключение к БД
	if err := initDB(); err != nil {
		log.Fatalf("❌ Ошибка подключения к БД: %v", err)
	}
	defer db.Close()

	r := mux.NewRouter()

	// Статические файлы
	r.PathPrefix("/auto.html").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "Authorization/auto.html")
	})
	r.PathPrefix("/script.js").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "Authorization/script.js")
	})
	r.PathPrefix("/styles.css").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "Authorization/styles.css")
	})
	r.PathPrefix("/admin.html").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "Admin/admin.html")
	})
	r.PathPrefix("/worker.html").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "workerpage/worker.html")
	})

	// API
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/validate-token", validateTokenHandler).Methods("POST", "OPTIONS")

	// CORS
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

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auto.html", http.StatusTemporaryRedirect)
	})

	fmt.Println("🚀 Сервер запущен: http://localhost:8080")
	fmt.Println("🔑 Admin: admin@tracking-system.com / admin123")
	fmt.Println("🔑 Worker: worker@tracking-system.com / worker123")

	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("❌ Ошибка сервера: %v", err)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fmt.Printf("❌ Ошибка декодирования: %v\n", err)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Неверный формат запроса"})
		return
	}

	fmt.Printf("📝 Попытка входа: %s\n", req.Email)

	user, err := getUserByEmail(req.Email)
	if err != nil {
		fmt.Printf("❌ Ошибка БД: %v\n", err)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Ошибка сервера: " + err.Error()})
		return
	}

	if user == nil {
		fmt.Println("❌ Пользователь не найден")
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Пользователь не найден"})
		return
	}

	if user.Password != req.Password {
		fmt.Println("❌ Неверный пароль")
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Неверный email или пароль"})
		return
	}

	token, err := generateToken(*user)
	if err != nil {
		fmt.Printf("❌ Ошибка токена: %v\n", err)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Ошибка создания токена"})
		return
	}

	fmt.Printf("✅ Вход успешен: %s (%s)\n", user.Email, user.Role)
	json.NewEncoder(w).Encode(LoginResponse{
		Success:     true,
		AccessToken: token,
		Role:        user.Role,
	})
}

func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenString == "" {
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
		"role":  claims.Role,
		"name":  claims.UserName,
	})
}
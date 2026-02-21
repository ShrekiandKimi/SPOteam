package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// JWT Claims - полная структура согласно статье
type Claims struct {
	jwt.RegisteredClaims
	UserID   string `json:"userId"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	UserName string `json:"name"`
	Issuer   string `json:"iss"` // Издатель токена
	Subject  string `json:"sub"` // Назначение токена
	Audience string `json:"aud"` // Аудитория
}

// RefreshClaims для refresh токена
type RefreshClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"userId"`
	TokenId string `json:"tokenId"` // Уникальный ID токена (jti)
}

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Name     string `json:"name"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success      bool   `json:"success"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	Message      string `json:"message,omitempty"`
	ExpiresIn    int64  `json:"expiresIn,omitempty"`
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// Конфигурация JWT
var (
	jwtSecret      = []byte("your-super-secret-key-change-in-production-2026!")
	refreshSecret  = []byte("your-refresh-secret-key-change-too-2026!")
	tokenExpiry    = 15 * time.Minute  // Access token: 15 минут
	refreshExpiry  = 7 * 24 * time.Hour // Refresh token: 7 дней
	issuer         = "staff-tracking-system"
	audience       = "staff-tracking-client"
)

// Blacklist для отозванных токенов (в продакшене используйте Redis)
var (
	tokenBlacklist = make(map[string]time.Time)
	blacklistMu    sync.RWMutex
)

// База пользователей (в продакшене используйте БД)
var users = []User{
	{
		ID:       "admin1",
		Email:    "admin@tracking-system.com",
		Password: "$2a$10$X.vKZkNlJ8uF9qQJ9qZ8uO7VxLxKxZxYxWxVxUxTxSxRxQxPxOxNxM", // admin123
		Role:     "admin",
		Name:     "Иван Петров",
	},
	{
		ID:       "worker1",
		Email:    "worker@tracking-system.com",
		Password: "$2a$10$X.vKZkNlJ8uF9qQJ9qZ8uO7VxLxKxZxYxWxVxUxTxSxRxQxPxOxNxM", // worker123
		Role:     "worker",
		Name:     "Алекс Петров",
	},
}

func main() {
	// Очистка blacklist каждые 5 минут
	go cleanupBlacklist()

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

	// API маршруты
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/refresh", refreshTokenHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/logout", logoutHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/validate-token", validateTokenHandler).Methods("POST", "OPTIONS")

	// CORS
	r.Use(corsMiddleware)

	// Главная → auto.html
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auto.html", http.StatusTemporaryRedirect)
	})

	fmt.Println("🚀 Сервер: http://localhost:8080")
	fmt.Println("🔑 Admin: admin@tracking-system.com / admin123")
	fmt.Println("🔑 Worker: worker@tracking-system.com / worker123")
	fmt.Printf("⏰ Access Token: %v\n", tokenExpiry)
	fmt.Printf("⏰ Refresh Token: %v\n", refreshExpiry)

	http.ListenAndServe(":8080", r)
}

// Генерация пары токенов
func generateTokenPair(user User) (*TokenPair, error) {
	// Генерация уникального ID для токена
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	tokenID := base64.URLEncoding.EncodeToString(randomBytes)

	// Создаем Access Token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Role,                    // sub - роль пользователя
			Issuer:    issuer,                       // iss - издатель
			Audience:  []string{audience},           // aud - аудитория
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiry)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        tokenID,                      // jti - уникальный ID
		},
		UserID:   user.ID,
		Email:    user.Email,
		Role:     user.Role,
		UserName: user.Name,
		Issuer:   issuer,
		Subject:  user.Role,
		Audience: audience,
	})

	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return nil, err
	}

	// Создаем Refresh Token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        tokenID + "_refresh",
		},
		UserID:  user.ID,
		TokenId: tokenID,
	})

	refreshTokenString, err := refreshToken.SignedString(refreshSecret)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

// Обработчик входа
func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Неверный формат запроса",
		})
		return
	}

	// Поиск пользователя
	var user *User
	for i := range users {
		if users[i].Email == req.Email {
			user = &users[i]
			break
		}
	}

	if user == nil {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Пользователь не найден",
		})
		return
	}

	// Проверка пароля (в демо используем простое сравнение)
	// В продакшене: bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if req.Password != "admin123" && req.Password != "worker123" {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Неверный пароль",
		})
		return
	}

	// Генерация токенов
	tokens, err := generateTokenPair(*user)
	if err != nil {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Ошибка создания токенов",
		})
		return
	}

	json.NewEncoder(w).Encode(LoginResponse{
		Success:      true,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int64(tokenExpiry.Seconds()),
	})
}

// Обновление токена
func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Проверка blacklist
	if isTokenBlacklisted(req.RefreshToken) {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Токен отозван",
		})
		return
	}

	// Валидация refresh токена
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return refreshSecret, nil
	})

	if err != nil || !token.Valid {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Неверный refresh токен",
		})
		return
	}

	// Поиск пользователя
	var user *User
	for i := range users {
		if users[i].ID == claims.UserID {
			user = &users[i]
			break
		}
	}

	if user == nil {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Пользователь не найден",
		})
		return
	}

	// Генерация новой пары токенов
	tokens, err := generateTokenPair(*user)
	if err != nil {
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Ошибка создания токенов",
		})
		return
	}

	json.NewEncoder(w).Encode(LoginResponse{
		Success:      true,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int64(tokenExpiry.Seconds()),
	})
}

// Выход из системы
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Добавляем токены в blacklist
	addToBlacklist(req.AccessToken, tokenExpiry)
	addToBlacklist(req.RefreshToken, refreshExpiry)

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// Проверка токена
func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Токен не предоставлен",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Проверка blacklist
	if isTokenBlacklisted(tokenString) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Токен отозван",
		})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Неверный токен",
		})
		return
	}

	// Проверка issuer и audience
	if claims.Issuer != issuer || claims.Audience != audience {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Неверный издатель или аудитория",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
		"role":  claims.Role,
		"name":  claims.UserName,
		"email": claims.Email,
	})
}

// CORS middleware
func corsMiddleware(next http.Handler) http.Handler {
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
}

// Blacklist функции
func addToBlacklist(token string, expiry time.Duration) {
	blacklistMu.Lock()
	defer blacklistMu.Unlock()
	tokenBlacklist[token] = time.Now().Add(expiry)
}

func isTokenBlacklisted(token string) bool {
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()
	expiry, exists := tokenBlacklist[token]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

func cleanupBlacklist() {
	for {
		time.Sleep(5 * time.Minute)
		blacklistMu.Lock()
		now := time.Now()
		for token, expiry := range tokenBlacklist {
			if now.After(expiry) {
				delete(tokenBlacklist, token)
			}
		}
		blacklistMu.Unlock()
	}
}
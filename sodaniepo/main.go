package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
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
	Phone    string `json:"phone"`
}

type User struct {
	ID       int
	Email    string
	Password string
	Role     string
	Name     string
	Phone    string
	Address  string
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

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Phone    string `json:"phone"`
}

type CreateServiceRequest struct {
	Title          string  `json:"title"`
	Price          float64 `json:"price"`
	Category       string  `json:"category"`
	Description    string  `json:"description"`
	Experience     int     `json:"experience"`
	Guarantee      int     `json:"guarantee"`
	CompletionTime string  `json:"completion_time"`
	Telegram       string  `json:"telegram"`
	Max            string  `json:"max"`
}

type Service struct {
	ID             int       `json:"id"`
	WorkerID       int       `json:"worker_id"`
	WorkerName     string    `json:"worker_name"`
	Title          string    `json:"title"`
	Price          float64   `json:"price"`
	Category       string    `json:"category"`
	Description    string    `json:"description"`
	Experience     int       `json:"experience"`
	Guarantee      int       `json:"guarantee"`
	CompletionTime string    `json:"completion_time"`
	Telegram       string    `json:"telegram"`
	Max            string    `json:"max"`
	Rating         float64   `json:"rating"`
	ReviewCount    int       `json:"review_count"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Order struct {
	ID               int       `json:"id"`
	CustomerID       int       `json:"customer_id"`
	WorkerID         int       `json:"worker_id,omitempty"`
	ServiceID        int       `json:"service_id,omitempty"`
	ServiceTitle     string    `json:"service_title"`
	ServiceDesc      string    `json:"service_description"`
	Price            float64   `json:"price"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	CustomerName     string    `json:"customer_name"`
	CustomerPhone    string    `json:"customer_phone"`
	CustomerAddress  string    `json:"customer_address"`
	WorkerName       string    `json:"worker_name,omitempty"`
	WorkerPhone      string    `json:"worker_phone,omitempty"`
	WorkerTelegram   string    `json:"worker_telegram,omitempty"`
	HasReview        bool      `json:"has_review,omitempty"`
}

type OrderRequest struct {
	ServiceTitle    string  `json:"service_title"`
	ServiceDesc     string  `json:"service_description"`
	Price           float64 `json:"price"`
	CustomerName    string  `json:"customer_name"`
	CustomerPhone   string  `json:"customer_phone"`
	CustomerAddress string  `json:"customer_address"`
	ServiceID       int     `json:"service_id,omitempty"`
}

type Review struct {
	ID           int       `json:"id"`
	CustomerID   int       `json:"customer_id"`
	WorkerID     int       `json:"worker_id"`
	OrderID      int       `json:"order_id"`
	Rating       int       `json:"rating"`
	Comment      string    `json:"comment"`
	CreatedAt    time.Time `json:"created_at"`
	CustomerName string    `json:"customer_name"`
}

type ReviewRequest struct {
	OrderID int    `json:"order_id"`
	Rating  int    `json:"rating"`
	Comment string `json:"comment"`
}

var (
	jwtSecret = []byte("your-secret-key-2026-change-in-production")
	db        *sql.DB
)

func initDB() error {
	connStr := "host=localhost port=5432 user=postgres password=1488 dbname=staff_tracking sslmode=disable"
	
	fmt.Println("Подключение к PostgreSQL...")
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("ошибка sql.Open: %v", err)
	}

	if err = db.Ping(); err != nil {
		return fmt.Errorf("ошибка db.Ping: %v", err)
	}

	fmt.Println("PostgreSQL подключен!")
	
	if err := createTables(); err != nil {
		return fmt.Errorf("ошибка создания таблиц: %v", err)
	}
	
	return nil
}

func createTables() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL,
			name VARCHAR(255) NOT NULL,
			phone VARCHAR(50),
			address TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS services (
			id SERIAL PRIMARY KEY,
			worker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			title VARCHAR(255) NOT NULL,
			price DECIMAL(10,2) NOT NULL,
			category VARCHAR(50) NOT NULL,
			description TEXT,
			experience INTEGER DEFAULT 0,
			guarantee INTEGER DEFAULT 0,
			completion_time VARCHAR(100),
			telegram VARCHAR(100),
			max VARCHAR(50),
			rating DECIMAL(3,2) DEFAULT 0.00,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS orders (
			id SERIAL PRIMARY KEY,
			customer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			worker_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
			service_id INTEGER REFERENCES services(id) ON DELETE SET NULL,
			admin_id INTEGER,
			service_title VARCHAR(255) NOT NULL,
			service_description TEXT,
			price DECIMAL(10,2) NOT NULL,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			customer_name VARCHAR(255) NOT NULL,
			customer_phone VARCHAR(50) NOT NULL,
			customer_address TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS reviews (
			id SERIAL PRIMARY KEY,
			customer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			worker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE UNIQUE,
			rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
			comment TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

func getUserByEmail(email string) (*User, error) {
	user := &User{}
	err := db.QueryRow(
		"SELECT id, email, password_hash, role, name, COALESCE(phone, ''), COALESCE(address, '') FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Email, &user.Password, &user.Role, &user.Name, &user.Phone, &user.Address)

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
		Phone:    user.Phone,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Неверный формат данных"})
		return
	}

	if req.Email == "" || req.Password == "" || req.Name == "" || req.Role == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Все поля обязательны"})
		return
	}
	if len(req.Password) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Пароль должен быть не менее 6 символов"})
		return
	}
	if req.Role != "customer" && req.Role != "worker" && req.Role != "admin" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Неверная роль"})
		return
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", req.Email).Scan(&exists)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Ошибка базы данных"})
		return
	}
	if exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Пользователь с таким email уже существует"})
		return
	}

	var userID int
	err = db.QueryRow(`
		INSERT INTO users (email, password_hash, role, name, phone, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
	`, req.Email, req.Password, req.Role, req.Name, req.Phone, time.Now(), time.Now()).Scan(&userID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Ошибка регистрации"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Регистрация успешна!",
		"email":   req.Email,
		"role":    req.Role,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req LoginRequest
	json.NewDecoder(r.Body).Decode(&req)

	user, err := getUserByEmail(req.Email)
	if err != nil {
		
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Ошибка сервера"})
		return
	}
	if user == nil || user.Password != req.Password {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Неверный email или пароль"})
		return
	}

	token, err := generateToken(*user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Ошибка генерации токена"})
		return
	}

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
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":  true,
		"role":   claims.Role,
		"name":   claims.UserName,
		"email":  claims.Email,
		"userId": claims.UserID,
		"phone":  claims.Phone,
	})
}

// 🔹 ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ
func getProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неавторизован"})
		return
	}

	user := &User{}
	err = db.QueryRow(
		"SELECT id, name, email, COALESCE(phone, ''), COALESCE(address, ''), role FROM users WHERE id = $1",
		claims.UserID,
	).Scan(&user.ID, &user.Name, &user.Email, &user.Phone, &user.Address, &user.Role)

	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Пользователь не найден"})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Ошибка БД"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user": map[string]interface{}{
			"id":      user.ID,
			"name":    user.Name,
			"email":   user.Email,
			"phone":   user.Phone,
			"address": user.Address,
			"role":    user.Role,
		},
	})
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method != "PUT" && r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Метод не разрешён"})
		return
	}
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неавторизован"})
		return
	}

	var req struct {
		Name    string `json:"name"`
		Phone   string `json:"phone"`
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неверный формат данных"})
		return
	}

	if req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Имя обязательно"})
		return
	}

	_, err = db.Exec(`
		UPDATE users 
		SET name = $1, phone = $2, address = $3, updated_at = CURRENT_TIMESTAMP 
		WHERE id = $4
	`, req.Name, req.Phone, req.Address, claims.UserID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Ошибка обновления"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Профиль обновлён"})
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неавторизован"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неверный формат данных"})
		return
	}

	if len(req.NewPassword) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Пароль должен быть не менее 6 символов"})
		return
	}

	var currentPassword string
	err = db.QueryRow("SELECT password_hash FROM users WHERE id = $1", claims.UserID).Scan(&currentPassword)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Пользователь не найден"})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Ошибка БД"})
		return
	}

	if currentPassword != req.CurrentPassword {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неверный текущий пароль"})
		return
	}

	_, err = db.Exec(`
		UPDATE users 
		SET password_hash = $1, updated_at = CURRENT_TIMESTAMP 
		WHERE id = $2
	`, req.NewPassword, claims.UserID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Ошибка обновления пароля"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Пароль изменён"})
}

func deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неавторизован"})
		return
	}

	_, err = db.Exec("DELETE FROM users WHERE id = $1", claims.UserID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Ошибка удаления"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Аккаунт удалён"})
}

// 🔹 АДМИНКА — НОВЫЕ ХЕНДЛЕРЫ

func getAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "admin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Требуется роль админа"})
		return
	}

	rows, err := db.Query(`
		SELECT id, name, email, COALESCE(phone, ''), role, created_at 
		FROM users 
		ORDER BY created_at DESC
	`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Ошибка БД"})
		return
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var name, email, phone, role string
		var createdAt time.Time
		
		rows.Scan(&id, &name, &email, &phone, &role, &createdAt)
		
		users = append(users, map[string]interface{}{
			"id":         id,
			"name":       name,
			"email":      email,
			"phone":      phone,
			"role":       role,
			"created_at": createdAt,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "users": users})
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "admin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Требуется роль админа"})
		return
	}

	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неверный ID"})
		return
	}

	if userID == claims.UserID {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Нельзя удалить себя"})
		return
	}

	_, err = db.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Ошибка удаления"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Пользователь удалён"})
}

func getPlatformStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "admin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Требуется роль админа"})
		return
	}

	var totalUsers, totalCustomers, totalWorkers, totalServices, totalOrders, totalReviews int
	var totalRevenue float64

	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
	db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'customer'").Scan(&totalCustomers)
	db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'worker'").Scan(&totalWorkers)
	db.QueryRow("SELECT COUNT(*) FROM services").Scan(&totalServices)
	db.QueryRow("SELECT COUNT(*) FROM orders").Scan(&totalOrders)
	db.QueryRow("SELECT COUNT(*) FROM reviews").Scan(&totalReviews)
	db.QueryRow("SELECT COALESCE(SUM(price), 0) FROM orders WHERE status = 'completed'").Scan(&totalRevenue)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"stats": map[string]interface{}{
			"total_users":     totalUsers,
			"total_customers": totalCustomers,
			"total_workers":   totalWorkers,
			"total_services":  totalServices,
			"total_orders":    totalOrders,
			"total_reviews":   totalReviews,
			"total_revenue":   totalRevenue,
		},
	})
}

func adminUpdateOrderStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "admin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Требуется роль админа"})
		return
	}

	var req struct {
		OrderID int    `json:"order_id"`
		Status  string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неверный формат данных"})
		return
	}

	_, err = db.Exec(`
		UPDATE orders 
		SET status = $1, updated_at = CURRENT_TIMESTAMP 
		WHERE id = $2
	`, req.Status, req.OrderID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Ошибка обновления"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Статус обновлён"})
}

// 🔹 КОНЕЦ АДМИН ХЕНДЛЕРОВ

func createServiceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "worker" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль исполнителя"})
		return
	}

	var req CreateServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Неверный формат данных"})
		return
	}

	if req.Title == "" || req.Price <= 0 || req.Category == "" || req.Description == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Заполните все обязательные поля"})
		return
	}

	_, err = db.Exec(`
		INSERT INTO services 
		(worker_id, title, price, category, description, experience, guarantee, completion_time, telegram, max, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, claims.UserID, req.Title, req.Price, req.Category, req.Description, req.Experience, req.Guarantee, req.CompletionTime, req.Telegram, req.Max, time.Now(), time.Now())

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка создания услуги"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Услуга создана"})
}

func updateServiceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "worker" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль исполнителя"})
		return
	}

	vars := mux.Vars(r)
	serviceID, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Неверный ID услуги"})
		return
	}

	var req CreateServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Неверный формат данных"})
		return
	}

	if req.Title == "" || req.Price <= 0 || req.Category == "" || req.Description == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Заполните все обязательные поля"})
		return
	}

	_, err = db.Exec(`
		UPDATE services 
		SET title = $1, price = $2, category = $3, description = $4, 
		    experience = $5, guarantee = $6, completion_time = $7, 
		    telegram = $8, max = $9, updated_at = CURRENT_TIMESTAMP
		WHERE id = $10 AND worker_id = $11
	`, req.Title, req.Price, req.Category, req.Description, req.Experience, 
	   req.Guarantee, req.CompletionTime, req.Telegram, req.Max, serviceID, claims.UserID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка обновления услуги"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Услуга обновлена"})
}

func getWorkerServicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "worker" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль исполнителя"})
		return
	}

	rows, err := db.Query(`
		SELECT id, worker_id, title, price, category, description, experience, guarantee, completion_time, telegram, max, rating, created_at, updated_at
		FROM services WHERE worker_id = $1 ORDER BY created_at DESC
	`, claims.UserID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД"})
		return
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var s Service
		rows.Scan(&s.ID, &s.WorkerID, &s.Title, &s.Price, &s.Category, &s.Description, &s.Experience, &s.Guarantee, &s.CompletionTime, &s.Telegram, &s.Max, &s.Rating, &s.CreatedAt, &s.UpdatedAt)
		services = append(services, s)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "services": services})
}

func deleteServiceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "worker" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль исполнителя"})
		return
	}

	vars := mux.Vars(r)
	serviceID, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Неверный ID услуги"})
		return
	}

	_, err = db.Exec("DELETE FROM services WHERE id = $1 AND worker_id = $2", serviceID, claims.UserID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка удаления услуги"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Услуга удалена"})
}

func getWorkerOrdersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "worker" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль исполнителя"})
		return
	}

	

	rows, err := db.Query(`
		SELECT o.id, o.customer_id, o.service_title, o.service_description, o.price, o.status, o.created_at, 
		       o.customer_name, o.customer_phone, o.customer_address, o.service_id
		FROM orders o
		WHERE o.worker_id = $1
		ORDER BY o.created_at DESC
	`, claims.UserID)
	if err != nil {
		
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД: " + err.Error()})
		return
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var o Order
		rows.Scan(&o.ID, &o.CustomerID, &o.ServiceTitle, &o.ServiceDesc, &o.Price, &o.Status, &o.CreatedAt, 
		          &o.CustomerName, &o.CustomerPhone, &o.CustomerAddress, &o.ServiceID)
		orders = append(orders, o)
	}
	
	
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "orders": orders})
}

func workerUpdateOrderStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "worker" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль исполнителя"})
		return
	}

	var req struct {
		OrderID int    `json:"order_id"`
		Status  string `json:"status"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	_, err = db.Exec(`
		UPDATE orders 
		SET status = $1, updated_at = CURRENT_TIMESTAMP 
		WHERE id = $2 AND worker_id = $3
	`, req.Status, req.OrderID, claims.UserID)
	
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка обновления статуса"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Статус обновлён"})
}

func getAllServicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	rows, err := db.Query(`
		SELECT s.id, s.worker_id, u.name as worker_name, s.title, s.price, s.category, s.description, 
		       s.experience, s.guarantee, s.completion_time, s.telegram, s.max, 
		       COALESCE(s.rating, 0.00), s.created_at, s.updated_at
		FROM services s
		JOIN users u ON s.worker_id = u.id
		ORDER BY s.created_at DESC
	`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД"})
		return
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var s Service
		rows.Scan(&s.ID, &s.WorkerID, &s.WorkerName, &s.Title, &s.Price, &s.Category, &s.Description, 
		          &s.Experience, &s.Guarantee, &s.CompletionTime, &s.Telegram, &s.Max, &s.Rating, &s.CreatedAt, &s.UpdatedAt)
		services = append(services, s)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "services": services})
}

func createOrderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "customer" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль клиента"})
		return
	}

	var req OrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Неверный формат данных"})
		return
	}

	var existingOrderCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM orders 
		WHERE customer_id = $1 AND service_id = $2 
		AND status NOT IN ('cancelled', 'rejected')
	`, claims.UserID, req.ServiceID).Scan(&existingOrderCount)
	
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка проверки заказа"})
		return
	}
	
	if existingOrderCount > 0 {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, 
			"message": "Вы уже заказывали эту услугу",
		})
		return
	}

	var workerID int
	err = db.QueryRow("SELECT worker_id FROM services WHERE id = $1", req.ServiceID).Scan(&workerID)
	if err != nil {
		
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Услуга не найдена"})
		return
	}

	_, err = db.Exec(`
		INSERT INTO orders (customer_id, worker_id, service_id, service_title, service_description, price, customer_name, customer_phone, customer_address, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
	`, claims.UserID, workerID, req.ServiceID, req.ServiceTitle, req.ServiceDesc, req.Price, req.CustomerName, req.CustomerPhone, req.CustomerAddress)

	if err != nil {
		fmt.Printf("❌ Ошибка создания заказа: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка создания заказа: " + err.Error()})
		return
	}

	
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Заказ создан"})
}

func getOrdersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "admin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль админа"})
		return
	}

	rows, err := db.Query(`
		SELECT id, customer_id, service_title, service_description, price, status, created_at, customer_name, customer_phone, customer_address
		FROM orders ORDER BY created_at DESC
	`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД"})
		return
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var o Order
		rows.Scan(&o.ID, &o.CustomerID, &o.ServiceTitle, &o.ServiceDesc, &o.Price, &o.Status, &o.CreatedAt, &o.CustomerName, &o.CustomerPhone, &o.CustomerAddress)
		orders = append(orders, o)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "orders": orders})
}

func updateOrderStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || (claims.Role != "admin" && claims.Role != "worker") {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль админа или исполнителя"})
		return
	}

	var req struct {
		OrderID int    `json:"order_id"`
		Status  string `json:"status"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	var query string
	var args []interface{}
	
	if claims.Role == "admin" {
		query = "UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
		args = []interface{}{req.Status, req.OrderID}
	} else {
		query = "UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND worker_id = $3"
		args = []interface{}{req.Status, req.OrderID, claims.UserID}
	}
	
	_, err = db.Exec(query, args...)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка обновления"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func getCustomerOrdersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "customer" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Требуется роль клиента"})
		return
	}

	rows, err := db.Query(`
		SELECT o.id, o.service_title, o.service_description, o.price, o.status, o.created_at,
		       o.worker_id, u.name as worker_name, u.phone as worker_phone,
		       COALESCE(s.telegram, '') as worker_telegram,
		       CASE WHEN EXISTS(SELECT 1 FROM reviews WHERE order_id = o.id) THEN true ELSE false END as has_review
		FROM orders o
		LEFT JOIN users u ON o.worker_id = u.id
		LEFT JOIN services s ON o.service_id = s.id
		WHERE o.customer_id = $1
		ORDER BY o.created_at DESC
	`, claims.UserID)
	if err != nil {
		
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД: " + err.Error()})
		return
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var o Order
		var workerID sql.NullInt64
		var hasReview bool
		var workerName, workerPhone, workerTelegram sql.NullString
		
		err := rows.Scan(&o.ID, &o.ServiceTitle, &o.ServiceDesc, &o.Price, &o.Status, &o.CreatedAt,
		          &workerID, &workerName, &workerPhone, &workerTelegram, &hasReview)
		if err != nil {
			
			continue
		}
		
		if workerID.Valid {
			o.WorkerID = int(workerID.Int64)
		}
		if workerName.Valid {
			o.WorkerName = workerName.String
		}
		if workerPhone.Valid {
			o.WorkerPhone = workerPhone.String
		}
		if workerTelegram.Valid {
			o.WorkerTelegram = workerTelegram.String
		}
		o.HasReview = hasReview
		
		orders = append(orders, o)
	}
	
	
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "orders": orders})
}

func createReviewHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "customer" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль клиента"})
		return
	}

	var req ReviewRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.Rating < 1 || req.Rating > 5 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Рейтинг должен быть от 1 до 5"})
		return
	}

	var workerID int
	err = db.QueryRow(`
		SELECT worker_id FROM orders 
		WHERE id = $1 AND customer_id = $2 AND status = 'completed'
	`, req.OrderID, claims.UserID).Scan(&workerID)
	
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Можно оставить отзыв только на завершённый заказ"})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД"})
		return
	}

	var exists bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM reviews WHERE order_id = $1)`, req.OrderID).Scan(&exists)
	if exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Вы уже оставили отзыв на этот заказ"})
		return
	}

	_, err = db.Exec(`
		INSERT INTO reviews (customer_id, worker_id, order_id, rating, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, claims.UserID, workerID, req.OrderID, req.Rating, req.Comment, time.Now())

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка создания отзыва"})
		return
	}

	_, err = db.Exec(`
		UPDATE services 
		SET rating = (
			SELECT COALESCE(AVG(r.rating), 0) 
			FROM reviews r 
			JOIN services s ON r.worker_id = s.worker_id 
			WHERE s.worker_id = $1
		)
		WHERE worker_id = $1
	`, workerID)

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Отзыв создан"})
}

func getWorkerReviewsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	vars := mux.Vars(r)
	workerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Неверный ID"})
		return
	}

	rows, err := db.Query(`
		SELECT r.id, r.customer_id, r.worker_id, r.order_id, r.rating, r.comment, r.created_at, u.name as customer_name
		FROM reviews r
		JOIN users u ON r.customer_id = u.id
		WHERE r.worker_id = $1
		ORDER BY r.created_at DESC
	`, workerID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД"})
		return
	}
	defer rows.Close()

	var reviews []Review
	for rows.Next() {
		var rev Review
		rows.Scan(&rev.ID, &rev.CustomerID, &rev.WorkerID, &rev.OrderID, &rev.Rating, &rev.Comment, &rev.CreatedAt, &rev.CustomerName)
		reviews = append(reviews, rev)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "reviews": reviews})
}

func cancelOrderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid || claims.Role != "customer" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль клиента"})
		return
	}

	vars := mux.Vars(r)
	orderID, err := strconv.Atoi(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Неверный ID заказа"})
		return
	}

	var status string
	err = db.QueryRow("SELECT status FROM orders WHERE id = $1 AND customer_id = $2", orderID, claims.UserID).Scan(&status)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Заказ не найден"})
		return
	}
	if status != "pending" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Можно отменить только заказ в статусе ожидания"})
		return
	}

	_, err = db.Exec("UPDATE orders SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = $1", orderID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка отмены заказа"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Заказ отменён"})
}

func main() {
	if err := initDB(); err != nil {
		log.Fatalf("Ошибка подключения к БД: %v", err)
	}
	defer db.Close()

	r := mux.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// 🔹 АВТОРИЗАЦИЯ
	r.HandleFunc("/api/register", registerHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/validate-token", validateTokenHandler).Methods("POST", "OPTIONS")
	
	// 🔹 ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ
	r.HandleFunc("/api/get-profile", getProfileHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/update-profile", updateProfileHandler).Methods("PUT", "POST", "OPTIONS")
	r.HandleFunc("/api/change-password", changePasswordHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/delete-account", deleteAccountHandler).Methods("DELETE", "OPTIONS")
	
	// 🔹 АДМИНКА
	r.HandleFunc("/api/get-all-users", getAllUsersHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/delete-user/{id}", deleteUserHandler).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/get-platform-stats", getPlatformStatsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/admin-update-order-status", adminUpdateOrderStatusHandler).Methods("POST", "OPTIONS")
	
	// 🔹 УСЛУГИ
	r.HandleFunc("/api/create-service", createServiceHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-worker-services", getWorkerServicesHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/delete-service/{id}", deleteServiceHandler).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/update-service/{id}", updateServiceHandler).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/get-worker-orders", getWorkerOrdersHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/worker-update-order-status", workerUpdateOrderStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-all-services", getAllServicesHandler).Methods("GET", "OPTIONS")
	
	// 🔹 ЗАКАЗЫ
	r.HandleFunc("/api/create-order", createOrderHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-orders", getOrdersHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/update-order-status", updateOrderStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-customer-orders", getCustomerOrdersHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/cancel-order/{id}", cancelOrderHandler).Methods("DELETE", "OPTIONS")
	
	// 🔹 ОТЗЫВЫ
	r.HandleFunc("/api/create-review", createReviewHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-worker-reviews/{id}", getWorkerReviewsHandler).Methods("GET", "OPTIONS")

	fmt.Println("Сервер запущен: http://localhost:8080")
	fmt.Println("API endpoints доступны на /api/*")

	http.ListenAndServe(":8080", r)
}
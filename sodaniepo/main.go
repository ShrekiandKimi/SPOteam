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
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Order struct {
	ID               int       `json:"id"`
	CustomerID       int       `json:"customer_id"`
	ServiceTitle     string    `json:"service_title"`
	ServiceDesc      string    `json:"service_description"`
	Price            float64   `json:"price"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	CustomerName     string    `json:"customer_name"`
	CustomerPhone    string    `json:"customer_phone"`
	CustomerAddress  string    `json:"customer_address"`
	ServiceID        int       `json:"service_id,omitempty"`
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

var (
	jwtSecret = []byte("your-secret-key-2026-change-in-production")
	db        *sql.DB
)

func initDB() error {
	connStr := "host=localhost port=5432 user=postgres password=Diegobrando8 dbname=staff_tracking sslmode=disable"
	
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
		INSERT INTO users (email, password_hash, role, name, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
	`, req.Email, req.Password, req.Role, req.Name, time.Now(), time.Now()).Scan(&userID)

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
		fmt.Printf("Ошибка БД: %v\n", err)
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
	})
}

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

// Новый хендлер: Получить заказы для услуг исполнителя
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
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД"})
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

// Новый хендлер: Исполнитель обновляет статус заказа
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
		SELECT s.id, s.worker_id, u.name as worker_name, s.title, s.price, s.category, s.description, s.experience, s.guarantee, s.completion_time, s.telegram, s.max, COALESCE(s.rating, 0.00), s.created_at, s.updated_at
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
		rows.Scan(&s.ID, &s.WorkerID, &s.WorkerName, &s.Title, &s.Price, &s.Category, &s.Description, &s.Experience, &s.Guarantee, &s.CompletionTime, &s.Telegram, &s.Max, &s.Rating, &s.CreatedAt, &s.UpdatedAt)
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
	json.NewDecoder(r.Body).Decode(&req)
	
	// Получаем worker_id из услуги
	var workerID *int
	if req.ServiceID > 0 {
		err = db.QueryRow("SELECT worker_id FROM services WHERE id = $1", req.ServiceID).Scan(&workerID)
	} else {
		err = db.QueryRow("SELECT worker_id FROM services WHERE title = $1 LIMIT 1", req.ServiceTitle).Scan(&workerID)
	}
	
	// Используем _ вместо result, так как результат не нужен
	if err == nil && workerID != nil {
		_, err = db.Exec(`
			INSERT INTO orders (customer_id, worker_id, service_id, service_title, service_description, price, customer_name, customer_phone, customer_address, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
		`, claims.UserID, *workerID, req.ServiceID, req.ServiceTitle, req.ServiceDesc, req.Price, req.CustomerName, req.CustomerPhone, req.CustomerAddress)
	} else {
		_, err = db.Exec(`
			INSERT INTO orders (customer_id, service_title, service_description, price, customer_name, customer_phone, customer_address, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
		`, claims.UserID, req.ServiceTitle, req.ServiceDesc, req.Price, req.CustomerName, req.CustomerPhone, req.CustomerAddress)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка создания заказа"})
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
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль клиента"})
		return
	}

	rows, err := db.Query(`
		SELECT id, service_title, service_description, price, status, created_at
		FROM orders WHERE customer_id = $1 ORDER BY created_at DESC
	`, claims.UserID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка БД"})
		return
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var o Order
		rows.Scan(&o.ID, &o.ServiceTitle, &o.ServiceDesc, &o.Price, &o.Status, &o.CreatedAt)
		orders = append(orders, o)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "orders": orders})
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

	r.HandleFunc("/api/register", registerHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/validate-token", validateTokenHandler).Methods("POST", "OPTIONS")
	
	r.HandleFunc("/api/create-service", createServiceHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-worker-services", getWorkerServicesHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/delete-service/{id}", deleteServiceHandler).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/update-service/{id}", updateServiceHandler).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/get-worker-orders", getWorkerOrdersHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/worker-update-order-status", workerUpdateOrderStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-all-services", getAllServicesHandler).Methods("GET", "OPTIONS")
	
	r.HandleFunc("/api/create-order", createOrderHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-orders", getOrdersHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/update-order-status", updateOrderStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-customer-orders", getCustomerOrdersHandler).Methods("GET", "OPTIONS")

	fmt.Println("Сервер запущен: http://localhost:8080")
	fmt.Println("API endpoints доступны на /api/*")

	http.ListenAndServe(":8080", r)
}
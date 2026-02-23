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

type Order struct {
	ID               int       `json:"id"`
	CustomerID       int       `json:"customer_id"`
	AdminID          int       `json:"admin_id"`
	ServiceTitle     string    `json:"service_title"`
	ServiceDesc      string    `json:"service_description"`
	Price            float64   `json:"price"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	CustomerName     string    `json:"customer_name"`
	CustomerPhone    string    `json:"customer_phone"`
	CustomerAddress  string    `json:"customer_address"`
}

type OrderRequest struct {
	ServiceTitle    string  `json:"service_title"`
	ServiceDesc     string  `json:"service_description"`
	Price           float64 `json:"price"`
	CustomerName    string  `json:"customer_name"`
	CustomerPhone   string  `json:"customer_phone"`
	CustomerAddress string  `json:"customer_address"`
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

func getUserByID(id int) (*User, error) {
	user := &User{}
	err := db.QueryRow(
		"SELECT id, email, password, role, name, COALESCE(phone, ''), COALESCE(address, '') FROM users WHERE id = $1",
		id,
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

func main() {
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
	r.PathPrefix("/customer.html").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "customer.html")
	})

	// API
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/validate-token", validateTokenHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/create-order", createOrderHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-orders", getOrdersHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/update-order-status", updateOrderStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get-customer-orders", getCustomerOrdersHandler).Methods("GET", "OPTIONS")

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

	fmt.Println("🚀 Сервер: http://localhost:8080")
	fmt.Println("👨‍💼 Admin: admin@tracking-system.com / admin123")
	fmt.Println("👤 Customer: customer@test.com / customer123")

	http.ListenAndServe(":8080", r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    var req LoginRequest
    json.NewDecoder(r.Body).Decode(&req)

    user, err := getUserByEmail(req.Email)
    if err != nil {
        // 🔹 Добавь эту строку для отладки:
        fmt.Printf("❌ Ошибка БД: %v\n", err)
        
        json.NewEncoder(w).Encode(LoginResponse{
            Success: false, 
            Message: "Ошибка сервера: " + err.Error(),
        })
        return
    }

    if user == nil || user.Password != req.Password {
        json.NewEncoder(w).Encode(LoginResponse{
            Success: false, 
            Message: "Неверный email или пароль",
        })
        return
    }

    token, _ := generateToken(*user)
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
		"email": claims.Email,
		"userId": claims.UserID,
	})
}

// Создание заказа (для клиента)
func createOrderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid || claims.Role != "customer" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль клиента"})
		return
	}

	var req OrderRequest
	json.NewDecoder(r.Body).Decode(&req)

	_, err = db.Exec(`
		INSERT INTO orders (customer_id, service_title, service_description, price, customer_name, customer_phone, customer_address, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
	`, claims.UserID, req.ServiceTitle, req.ServiceDesc, req.Price, req.CustomerName, req.CustomerPhone, req.CustomerAddress)

	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка создания заказа"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Заказ создан"})
}

// Получить все заказы (для админа)
func getOrdersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid || claims.Role != "admin" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль админа"})
		return
	}

	rows, err := db.Query(`
		SELECT id, customer_id, service_title, service_description, price, status, created_at, customer_name, customer_phone, customer_address
		FROM orders ORDER BY created_at DESC
	`)
	if err != nil {
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

// Обновить статус заказа (для админа)
func updateOrderStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid || claims.Role != "admin" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль админа"})
		return
	}

	var req struct {
		OrderID int    `json:"order_id"`
		Status  string `json:"status"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	_, err = db.Exec("UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", req.Status, req.OrderID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Ошибка обновления"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// Получить заказы клиента
func getCustomerOrdersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid || claims.Role != "customer" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Требуется роль клиента"})
		return
	}

	rows, err := db.Query(`
		SELECT id, service_title, service_description, price, status, created_at
		FROM orders WHERE customer_id = $1 ORDER BY created_at DESC
	`, claims.UserID)
	if err != nil {
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
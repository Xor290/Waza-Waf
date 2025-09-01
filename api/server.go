package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

var jwtSecret = []byte("MonSecretSuperSecurise123")

var db *sql.DB

type User struct {
	ID       int
	Username string
	Password string
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// =====================================
// Initialisation de la DB
// =====================================
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./waf.db")
	if err != nil {
		panic(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password TEXT
	);`
	_, err = db.Exec(createTable)
	if err != nil {
		panic(err)
	}

	// Ajouter un utilisateur par défaut si inexistant
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)
	if err != nil {
		panic(err)
	}
	if count == 0 {
		_, _ = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", "admin", "admin123")
		fmt.Println("Utilisateur admin créé: admin/admin123")
	}
}

// =====================================
// Login handler
// =====================================
func loginHandler(c *gin.Context) {
	var creds Login
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON invalide"})
		return
	}

	// Vérifier dans la DB
	var dbPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", creds.Username).Scan(&dbPassword)
	if err != nil || dbPassword != creds.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Nom d'utilisateur ou mot de passe incorrect"})
		return
	}

	// Générer JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": creds.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Impossible de générer le token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// =====================================
// Middleware JWT
// =====================================
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token manquant"})
			c.Abort()
			return
		}

		tokenString := authHeader[len("Bearer "):]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrTokenMalformed
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalide"})
			c.Abort()
			return
		}

		c.Set("user", token.Claims.(jwt.MapClaims)["username"])
		c.Next()
	}
}

// =====================================
// Endpoint protégé
// =====================================
func statsHandler(c *gin.Context) {
	// Pour exemple : stats fictives, à remplacer par stats réelles du WAF
	c.JSON(http.StatusOK, gin.H{
		"stats": map[string]interface{}{
			"127.0.0.1": map[string]int{"total": 10, "safe": 7, "blocked": 3},
		},
	})
}

// =====================================
// Main
// =====================================
func main() {
	initDB()

	r := gin.Default()
	r.POST("/login", loginHandler)

	protected := r.Group("/api")
	protected.Use(authMiddleware())
	protected.GET("/stats", statsHandler)

	fmt.Println("API démarrée sur :8080")
	r.Run(":8080")
}

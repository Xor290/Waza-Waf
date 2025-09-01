package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"waza_serveur/db"
)

// Clé secrète pour signer le JWT (32 bytes)
var jwtSecret = []byte("32byteslongsecretkeyforjwt1234567890")

// Clé AES pour chiffrer le JWT (32 bytes)
var encryptionKey = []byte("12345678901234567890123456789012")
type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ================= LOGIN =================
func LoginHandler(c *gin.Context) {
	var creds Login
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON invalide"})
		return
	}

	// Vérifier dans la DB (mot de passe en clair)
	var dbPassword string
	err := db.DB.QueryRow("SELECT password FROM users WHERE username = ?", creds.Username).Scan(&dbPassword)
	if err != nil || dbPassword != creds.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Nom d'utilisateur ou mot de passe incorrect"})
		return
	}

	// Générer JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": creds.Username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Impossible de générer le token"})
		return
	}

	// Chiffrer le JWT
	encryptedToken, err := encryptAES(tokenString, encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Impossible de chiffrer le token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": encryptedToken})
}

// ================= MIDDLEWARE =================
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token manquant"})
			c.Abort()
			return
		}

		tokenEncrypted := authHeader[len("Bearer "):]
		tokenString, err := decryptAES(tokenEncrypted, encryptionKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalide (décryptage)"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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

// ================= AES =================
func encryptAES(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nil, nonce, []byte(plainText), nil)
	result := append(nonce, cipherText...)
	return base64.StdEncoding.EncodeToString(result), nil
}

func decryptAES(cipherTextBase64 string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", err
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

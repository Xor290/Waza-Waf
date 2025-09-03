package main

import (
    "fmt"
    "waza_serveur/db"
    "waza_serveur/handlers"
    "waza_serveur/udp" // Nouveau package pour UDP
    "github.com/gin-gonic/gin"
)

func main() {
    // Initialisation de la base de données
    db.InitDB()
    
    // Démarrage du serveur UDP en arrière-plan
    go udp.StartUDPServer(514) 
    
    r := gin.Default()
    r.Static("/static", "./static")
    
    // Routes publiques
    r.POST("/login", handlers.LoginHandler)
    
    protected := r.Group("/api")
    protected.Use(handlers.AuthMiddleware())
    {
        protected.GET("/stats", handlers.StatsHandler)
        protected.GET("/logs", handlers.LogsHandler)     // Nouveaux endpoints
        protected.GET("/alerts", handlers.AlertsHandler) // pour les logs UDP
        protected.POST("/reset-stats", handlers.ResetStatsHandler)
    }
    
    // Route de santé du système
    r.GET("/health", handlers.HealthHandler)
    
    fmt.Println("API démarrée sur :8080")
    fmt.Println("Serveur UDP actif sur le port 514")
    r.Run(":8080")
}
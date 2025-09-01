package main

import (
	"fmt"
	"waf_serveur/db"
	"waf_serveur/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	db.InitDB()

	r := gin.Default()

	r.Static("/static", "./static")

	r.POST("/login", handlers.LoginHandler)

	protected := r.Group("/api")
	protected.Use(handlers.AuthMiddleware())
	protected.GET("/stats", handlers.StatsHandler)

	fmt.Println("API démarrée sur :8080")
	r.Run(":8080")

}

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type AgentStats struct {
	Total   int `json:"Total"`
	Safe    int `json:"Safe"`
	Blocked int `json:"Blocked"`
}

func StatsHandler(c *gin.Context) {
	// Exemple : données mockées
	stats := map[string]AgentStats{
		"192.168.1.10": {Total: 120, Safe: 100, Blocked: 20},
		"192.168.1.11": {Total: 90, Safe: 80, Blocked: 10},
	}

	c.JSON(http.StatusOK, stats)
}

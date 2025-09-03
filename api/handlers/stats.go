package handlers

import (
    "net/http"
    "strconv"
    "time"
    "waza_serveur/udp"
    "github.com/gin-gonic/gin"
)

func StatsHandler(c *gin.Context) {
    stats := udp.GetStats()
    
    if len(stats) == 0 {
        mockStats := map[string]udp.AgentStats{
            "192.168.1.10": {Total: 120, Safe: 100, Blocked: 20, LastUpdate: time.Now()},
            "192.168.1.11": {Total: 90, Safe: 80, Blocked: 10, LastUpdate: time.Now()},
        }
        c.JSON(http.StatusOK, gin.H{
            "success": true,
            "data":    mockStats,
            "source":  "mock", 
        })
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "data":    stats,
        "source":  "udp", 
    })
}

func LogsHandler(c *gin.Context) {
    limitStr := c.DefaultQuery("limit", "50")
    limit, err := strconv.Atoi(limitStr)
    if err != nil || limit <= 0 {
        limit = 50
    }
    
    logs := udp.GetRecentLogs(limit)
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "data":    logs,
        "count":   len(logs),
    })
}

func AlertsHandler(c *gin.Context) {
    alerts := udp.GetAlerts()
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "data":    alerts,
        "count":   len(alerts),
    })
}

func ResetStatsHandler(c *gin.Context) {
    udp.ResetStats()
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Statistiques réinitialisées avec succès",
    })
}

func HealthHandler(c *gin.Context) {
    systemInfo := udp.GetSystemInfo()
    
    c.JSON(http.StatusOK, gin.H{
        "success":   true,
        "status":    "ok",
        "timestamp": time.Now(),
        "system":    systemInfo,
    })
}
package udp

import (
    "fmt"
    "log"
    "net"
    "strings"
    "sync"
    "time"
)

type LogEntry struct {
    ID        int       `json:"id"`
    Timestamp time.Time `json:"timestamp"`
    Message   string    `json:"message"`
    SourceIP  string    `json:"source_ip"`
    SenderIP  string    `json:"sender_ip"`
    IsAlert   bool      `json:"is_alert"`
    LogType   string    `json:"log_type"`
}

type AgentStats struct {
    Total   int `json:"total"`
    Safe    int `json:"safe"`
    Blocked int `json:"blocked"`
    LastUpdate time.Time `json:"last_update"`
}

var (
    statsData = make(map[string]*AgentStats)
    statsMutex sync.RWMutex
    logEntries []LogEntry
    logMutex   sync.RWMutex
    logIDCounter int
)

func StartUDPServer(port int) {
    addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
    if err != nil {
        log.Fatal("Erreur résolution adresse UDP:", err)
    }

    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Fatal("Erreur écoute UDP:", err)
    }
    defer conn.Close()

    log.Printf("Serveur UDP démarré sur le port %d", port)

    buffer := make([]byte, 4096)
    
    for {
        n, clientAddr, err := conn.ReadFromUDP(buffer)
        if err != nil {
            log.Printf("Erreur lecture UDP: %v", err)
            continue
        }

        logLine := strings.TrimSpace(string(buffer[:n]))
        if logLine != "" {
            log.Printf("Log reçu de %s: %s", clientAddr.IP, logLine)
            processLogEntry(logLine, clientAddr.IP.String())
        }
    }
}

func extractSourceIP(logLine string) string {
    if strings.Contains(logLine, "src_ip=") {
        parts := strings.Split(logLine, "src_ip=")
        if len(parts) > 1 {
            ipPart := strings.Fields(parts[1])[0]
            if net.ParseIP(ipPart) != nil {
                return ipPart
            }
        }
    }
    
    fields := strings.Fields(logLine)
    for _, field := range fields {
        cleanField := strings.Trim(field, "[]():,")
        if net.ParseIP(cleanField) != nil {
            return cleanField
        }
    }
    
    return "unknown"
}

func getLogType(logLine string) string {
    logUpper := strings.ToUpper(logLine)
    
    if strings.Contains(logUpper, "ALERT") {
        return "ALERT"
    } else if strings.Contains(logUpper, "BLOCK") {
        return "BLOCKED"
    } else if strings.Contains(logUpper, "ALLOW") {
        return "ALLOWED"
    } else if strings.Contains(logUpper, "WARN") {
        return "WARNING"
    }
    
    return "INFO"
}

// processLogEntry traite une entrée de log
func processLogEntry(logLine string, senderIP string) {
    sourceIP := extractSourceIP(logLine)
    logType := getLogType(logLine)
    isAlert := logType == "ALERT" || logType == "BLOCKED"
    
    // Stockage du log
    logMutex.Lock()
    logIDCounter++
    entry := LogEntry{
        ID:        logIDCounter,
        Timestamp: time.Now(),
        Message:   logLine,
        SourceIP:  sourceIP,
        SenderIP:  senderIP,
        IsAlert:   isAlert,
        LogType:   logType,
    }
    
    logEntries = append(logEntries, entry)
    
    if len(logEntries) > 1000 {
        logEntries = logEntries[1:]
    }
    logMutex.Unlock()

    updateStats(sourceIP, isAlert)
}

func updateStats(sourceIP string, isAlert bool) {
    statsMutex.Lock()
    defer statsMutex.Unlock()
    
    if statsData[sourceIP] == nil {
        statsData[sourceIP] = &AgentStats{
            Total: 0, 
            Safe: 0, 
            Blocked: 0,
            LastUpdate: time.Now(),
        }
    }
    
    statsData[sourceIP].Total++
    statsData[sourceIP].LastUpdate = time.Now()
    
    if isAlert {
        statsData[sourceIP].Blocked++
    } else {
        statsData[sourceIP].Safe++
    }
}

func GetStats() map[string]AgentStats {
    statsMutex.RLock()
    defer statsMutex.RUnlock()
    
    stats := make(map[string]AgentStats)
    for ip, data := range statsData {
        stats[ip] = *data
    }
    
    return stats
}

func GetRecentLogs(limit int) []LogEntry {
    logMutex.RLock()
    defer logMutex.RUnlock()
    
    if limit <= 0 || limit > len(logEntries) {
        limit = len(logEntries)
    }
    
    if len(logEntries) == 0 {
        return []LogEntry{}
    }
    
    startIndex := len(logEntries) - limit
    result := make([]LogEntry, limit)
    copy(result, logEntries[startIndex:])
    
    return result
}

func GetAlerts() []LogEntry {
    logMutex.RLock()
    defer logMutex.RUnlock()
    
    var alerts []LogEntry
    for _, entry := range logEntries {
        if entry.IsAlert {
            alerts = append(alerts, entry)
        }
    }
    
    return alerts
}

func ResetStats() {
    statsMutex.Lock()
    statsData = make(map[string]*AgentStats)
    statsMutex.Unlock()
    
    logMutex.Lock()
    logEntries = []LogEntry{}
    logIDCounter = 0
    logMutex.Unlock()
}

func GetSystemInfo() map[string]interface{} {
    statsMutex.RLock()
    logMutex.RLock()
    defer statsMutex.RUnlock()
    defer logMutex.RUnlock()
    
    return map[string]interface{}{
        "stats_count": len(statsData),
        "logs_count":  len(logEntries),
        "uptime":     time.Since(startTime),
    }
}

var startTime = time.Now()
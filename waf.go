package main

import (
    "encoding/json"
    "encoding/base64"
    "io"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "regexp"
    "fmt"
    "strings"
    "html"
    "unicode/utf8"
    "sync"
    "context"
    "time"
)

var (
    fileLogger   *log.Logger
    loggerMutex  sync.RWMutex
    logFile      *os.File
)

func init() {
    var err error
    logFile, err = os.OpenFile("waf.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Impossible d'ouvrir le fichier de log: %v", err)
    }
    fileLogger = log.New(logFile, "", log.LstdFlags)
}

// Thread-safe logging function
func safeLog(message string) {
    loggerMutex.Lock()
    defer loggerMutex.Unlock()
    log.Println(message)
    fileLogger.Println(message)
}

// Structure pour les métriques de performance
type RequestMetrics struct {
    mu              sync.RWMutex
    totalRequests   int64
    blockedRequests int64
    activeRequests  int64
}

func (rm *RequestMetrics) IncrementTotal() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    rm.totalRequests++
}

func (rm *RequestMetrics) IncrementBlocked() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    rm.blockedRequests++
}

func (rm *RequestMetrics) IncrementActive() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    rm.activeRequests++
}

func (rm *RequestMetrics) DecrementActive() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    rm.activeRequests--
}

func (rm *RequestMetrics) GetStats() (int64, int64, int64) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    return rm.totalRequests, rm.blockedRequests, rm.activeRequests
}

var metrics = &RequestMetrics{}

// Structure pour gérer le contexte de la requête
type RequestContext struct {
    ID        string
    IP        string
    Method    string
    Path      string
    StartTime time.Time
}

// Worker pool pour traiter les requêtes
type WorkerPool struct {
    workers    int
    jobQueue   chan RequestJob
    wg         sync.WaitGroup
    ctx        context.Context
    cancel     context.CancelFunc
}

type RequestJob struct {
    w       http.ResponseWriter
    r       *http.Request
    proxy   *httputil.ReverseProxy
    patterns *PatternManager
    limiter *rateLimiter
    banIPs  *BanIPs
    reqCtx  *RequestContext
}

func NewWorkerPool(workers int) *WorkerPool {
    ctx, cancel := context.WithCancel(context.Background())
    return &WorkerPool{
        workers:  workers,
        jobQueue: make(chan RequestJob, workers*2), // Buffer pour éviter le blocage
        ctx:      ctx,
        cancel:   cancel,
    }
}

func (wp *WorkerPool) Start() {
    for i := 0; i < wp.workers; i++ {
        wp.wg.Add(1)
        go wp.worker(i)
    }
}

func (wp *WorkerPool) Stop() {
    wp.cancel()
    close(wp.jobQueue)
    wp.wg.Wait()
}

func (wp *WorkerPool) Submit(job RequestJob) {
    select {
    case wp.jobQueue <- job:
    case <-wp.ctx.Done():
        http.Error(job.w, "Service unavailable", http.StatusServiceUnavailable)
    default:
        // Si la queue est pleine, traiter directement pour éviter la perte de requêtes
        go wp.processRequest(job)
    }
}

func (wp *WorkerPool) worker(id int) {
    defer wp.wg.Done()
    safeLog(fmt.Sprintf("[WORKER] Worker %d démarré", id))
    
    for {
        select {
        case job, ok := <-wp.jobQueue:
            if !ok {
                safeLog(fmt.Sprintf("[WORKER] Worker %d arrêté", id))
                return
            }
            wp.processRequest(job)
        case <-wp.ctx.Done():
            safeLog(fmt.Sprintf("[WORKER] Worker %d arrêté par contexte", id))
            return
        }
    }
}

func (wp *WorkerPool) processRequest(job RequestJob) {
    defer func() {
        if r := recover(); r != nil {
            safeLog(fmt.Sprintf("[ERROR] Panic lors du traitement de la requête %s: %v", job.reqCtx.ID, r))
            http.Error(job.w, "Internal server error", http.StatusInternalServerError)
        }
        metrics.DecrementActive()
    }()

    metrics.IncrementActive()
    processWAFRequest(job.w, job.r, job.proxy, job.patterns, job.limiter, job.banIPs, job.reqCtx)
}

// Global worker pool
var workerPool *WorkerPool

func InitWorkerPool(workers int) {
    workerPool = NewWorkerPool(workers)
    workerPool.Start()
}

func StopWorkerPool() {
    if workerPool != nil {
        workerPool.Stop()
    }
    if logFile != nil {
        logFile.Close()
    }
}

// Handler principal du WAF avec support multi-threading
func WAFHandler(proxy *httputil.ReverseProxy, patterns *PatternManager, limiter *rateLimiter, banIPs *BanIPs) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        metrics.IncrementTotal()
        
        // Créer un contexte unique pour cette requête
        reqCtx := &RequestContext{
            ID:        generateRequestID(),
            IP:        getClientIP(r),
            Method:    r.Method,
            Path:      r.URL.Path,
            StartTime: time.Now(),
        }

        safeLog(fmt.Sprintf("[INFO] [%s] Requête reçue de %s : %s %s", 
            reqCtx.ID, reqCtx.IP, reqCtx.Method, reqCtx.Path))

        // Soumettre la requête au worker pool
        job := RequestJob{
            w:       w,
            r:       r,
            proxy:   proxy,
            patterns: patterns,
            limiter: limiter,
            banIPs:  banIPs,
            reqCtx:  reqCtx,
        }

        workerPool.Submit(job)
    }
}

// Génère un ID unique pour chaque requête
func generateRequestID() string {
    return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

// Extrait l'IP du client en tenant compte des proxys
func getClientIP(r *http.Request) string {
    // Vérifier les headers de proxy couramment utilisés
    if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
        return strings.Split(ip, ",")[0]
    }
    if ip := r.Header.Get("X-Real-IP"); ip != "" {
        return ip
    }
    if ip := r.Header.Get("X-Client-IP"); ip != "" {
        return ip
    }
    return r.RemoteAddr
}

// Traite la requête WAF (ancienne logique WAFHandler)
func processWAFRequest(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, 
    patterns *PatternManager, limiter *rateLimiter, banIPs *BanIPs, reqCtx *RequestContext) {
    
    startTime := time.Now()
    defer func() {
        duration := time.Since(startTime)
        safeLog(fmt.Sprintf("[PERF] [%s] Requête traitée en %v", reqCtx.ID, duration))
    }()

    // Limitation par IP (thread-safe car les limiters sont conçus pour être thread-safe)
    if !limiter.Allow(reqCtx.IP) {
        metrics.IncrementBlocked()
        safeLog(fmt.Sprintf("[WARN] [%s] IP bannie temporairement : %s", reqCtx.ID, reqCtx.IP))
        http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
        return
    }

    if !banIPs.AllowBanIp(reqCtx.IP) {
        metrics.IncrementBlocked()
        safeLog(fmt.Sprintf("[WARN] [%s] IP bannie définitivement : %s", reqCtx.ID, reqCtx.IP))
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Vérification du payload avec timeout pour éviter les blocages
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    done := make(chan bool, 1)
    var blocked bool

    go func() {
        blocked = checkTypePayload(w, r, patterns, reqCtx)
        done <- true
    }()

    select {
    case <-done:
        if blocked {
            metrics.IncrementBlocked()
            return
        }
    case <-ctx.Done():
        safeLog(fmt.Sprintf("[ERROR] [%s] Timeout lors de la vérification du payload", reqCtx.ID))
        http.Error(w, "Request Timeout", http.StatusRequestTimeout)
        return
    }

    // Si tout est OK, forward vers le backend
    safeLog(fmt.Sprintf("[PASS] [%s] Requête autorisée. IP: %s, URL: %s", 
        reqCtx.ID, reqCtx.IP, reqCtx.Path))
    proxy.ServeHTTP(w, r)
}

// Version thread-safe de checkTypePayload
func checkTypePayload(w http.ResponseWriter, r *http.Request, patterns *PatternManager, reqCtx *RequestContext) bool {
    // Charger la config de manière thread-safe
    config, err := LoadAlertConfig("config.yaml")
    if err != nil {
        safeLog(fmt.Sprintf("[ERROR] [%s] Erreur lors du chargement de la config: %v", reqCtx.ID, err))
    }

    // Parse form data avec protection contre les attaques de déni de service
    r.ParseForm()
    for key, values := range r.Form {
        for _, value := range values {
            if patterns.IsMalicious(value) {
                safeLog(fmt.Sprintf("[BLOCK] [%s] Paramètre suspect. IP: %s, Param: %s, Valeur: %s", 
                    reqCtx.ID, reqCtx.IP, key, truncateString(value, 100)))
                http.Error(w, "Requête bloquée par WAF (paramètres)", http.StatusForbidden)
                
                // Envoi d'alerte asynchrone pour ne pas bloquer le traitement
                go func() {
                    SendAlert(config, fmt.Sprintf("Attaque détectée! IP: %s, Param: %s, Valeur: %s", 
                        reqCtx.IP, key, truncateString(value, 100)))
                }()
                return true
            }
        }
    }

    // Lecture du body avec limite de taille pour éviter les attaques DoS
    body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // Limite à 10MB
    if err != nil {
        safeLog(fmt.Sprintf("[ERROR] [%s] Erreur lors de la lecture du body: %v", reqCtx.ID, err))
        http.Error(w, "Bad Request", http.StatusBadRequest)
        return true
    }
    r.Body = io.NopCloser(strings.NewReader(string(body)))

    // Analyser différents types de contenu
    bodyStr := string(body)
    
    switch {
    case checkJSONBody(body, patterns):
        safeLog(fmt.Sprintf("[BLOCK] [%s] Payload JSON suspect. IP: %s", reqCtx.ID, reqCtx.IP))
        http.Error(w, "Requête bloquée par WAF (JSON)", http.StatusForbidden)
        return true

    case analyzeHTMLEntities(bodyStr):
        safeLog(fmt.Sprintf("[BLOCK] [%s] Payload HTML entities suspect. IP: %s", reqCtx.ID, reqCtx.IP))
        http.Error(w, "Requête bloquée par WAF (HTML entities)", http.StatusForbidden)
        return true

    case analyzeURLEncoding(bodyStr):
        safeLog(fmt.Sprintf("[BLOCK] [%s] Payload URL encode suspect. IP: %s", reqCtx.ID, reqCtx.IP))
        http.Error(w, "Requête bloquée par WAF (URL encode)", http.StatusForbidden)
        return true

    case isBase64(bodyStr) && len(bodyStr) > 100: // Éviter les faux positifs sur de petites chaînes
        safeLog(fmt.Sprintf("[BLOCK] [%s] Payload Base64 suspect. IP: %s", reqCtx.ID, reqCtx.IP))
        http.Error(w, "Requête bloquée par WAF (Base64)", http.StatusForbidden)
        return true

    case strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data"):
        r.ParseMultipartForm(32 << 20) // 32MB max
        if checkMultipartBody(r, patterns) {
            safeLog(fmt.Sprintf("[BLOCK] [%s] Fichier suspect détecté. IP: %s", reqCtx.ID, reqCtx.IP))
            http.Error(w, "Requête bloquée par WAF (fichier)", http.StatusForbidden)
            return true
        }
    }

    return false
}

// Utility function pour tronquer les chaînes longues dans les logs
func truncateString(s string, maxLen int) string {
    if len(s) <= maxLen {
        return s
    }
    return s[:maxLen] + "..."
}

// Handler pour les métriques de performance
func MetricsHandler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        total, blocked, active := metrics.GetStats()
        
        response := map[string]interface{}{
            "total_requests":   total,
            "blocked_requests": blocked,
            "active_requests":  active,
            "block_rate":       float64(blocked) / float64(total) * 100,
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }
}

// Fonctions existantes inchangées mais thread-safe par design
func containsURLEncoding(s string) bool {
    re := regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
    return re.MatchString(s)
}

func analyzeURLEncoding(s string) bool {
    if containsURLEncoding(s) {
        decoded := s
        for i := 0; i < 3; i++ {
            tmp, err := url.QueryUnescape(decoded)
            if err != nil || tmp == decoded {
                break
            }
            decoded = tmp
        }

        suspiciousKeywords := []string{"<script", "onerror", "SELECT", "UNION", "DROP"}
        for _, kw := range suspiciousKeywords {
            if strings.Contains(strings.ToLower(decoded), strings.ToLower(kw)) {
                return true 
            }
        }
    }
    return false
}

func containsHTMLEntities(s string) bool {
    re := regexp.MustCompile(`&[a-zA-Z0-9#]+;`)
    return re.MatchString(s)
}

func analyzeHTMLEntities(s string) bool {
    if containsHTMLEntities(s) {
        decoded := html.UnescapeString(s)
        suspiciousKeywords := []string{"<script", "onerror", "SELECT", "UNION", "DROP"}

        for _, kw := range suspiciousKeywords {
            if strings.Contains(strings.ToLower(decoded), strings.ToLower(kw)) {
                return true
            }
        }
    }
    return false
}

func isBase64(s string) bool {
    if len(s)%4 != 0 || len(s) < 4 {
        return false
    }
    matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]+={0,2}$`, s)
    if !matched {
        return false
    }
    data, err := base64.StdEncoding.DecodeString(s)
    if err != nil {
        return false
    }
    return utf8.Valid(data)
}

func checkJSONBody(body []byte, patterns *PatternManager) bool {
    var data interface{}
    if err := json.Unmarshal(body, &data); err != nil {
        return false
    }
    return traverseJSON(data, patterns)
}

func traverseJSON(v interface{}, pm *PatternManager) bool {
    switch t := v.(type) {
    case string:
        if pm.IsMalicious(t) {
            return true
        }
    case map[string]interface{}:
        for _, val := range t {
            if traverseJSON(val, pm) {
                return true
            }
        }
    case []interface{}:
        for _, val := range t {
            if traverseJSON(val, pm) {
                return true
            }
        }
    }
    return false
}

func checkMultipartBody(r *http.Request, patterns *PatternManager) bool {
    if r.MultipartForm == nil {
        return false
    }
    for _, files := range r.MultipartForm.File {
        for _, fileHeader := range files {
            f, err := fileHeader.Open()
            if err != nil {
                continue
            }
            // Limite la lecture à 1MB par fichier pour éviter les attaques DoS
            content, _ := io.ReadAll(io.LimitReader(f, 1024*1024))
            f.Close()
            if patterns.IsMalicious(string(content)) {
                return true
            }
        }
    }
    return false
}
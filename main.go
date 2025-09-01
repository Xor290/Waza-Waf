package main

import (
    "fmt"
    "net/http"
    "net/http/httputil"
    "net/url"
    "time"
)



func main() {
    // Charger les patterns depuis fichier - FIXED: patterns is now *PatternManager
    patterns := LoadPatterns("payloads.txt")
   
    // Démarrer la surveillance automatique des patterns (rechargement toutes les 30 secondes)
    patterns.StartWatcher(30 * time.Second)
   
    // Configurer le serveur backend
    backend, _ := url.Parse("http://127.0.0.1:8000")
    proxy := httputil.NewSingleHostReverseProxy(backend)
   
    // Limiteur : 100 req/sec avec ban 10 min
    limiter := NewRateLimiter(100, 1*time.Second, 10*time.Minute)
    banIPs := NewBanIPs(300, 10*time.Minute)
   
    // Handler WAF - FIXED: Now passing *PatternManager instead of []*regexp.Regexp
    http.HandleFunc("/", WAFHandler(proxy, patterns, limiter, banIPs))
   
    fmt.Printf("WAF Reverse Proxy Go multi-fichiers démarré sur :8080\n")
    fmt.Printf("Patterns chargés: %d\n", patterns.GetPatternsCount())
    fmt.Println("Backend configuré: http://127.0.0.1:8000")
    
    http.ListenAndServe(":8080", nil)
}
package main

import (
    "bufio"
    "log"
    "os"
    "sync"
    "time"
)

type rateLimiter struct {
    requests map[string][]time.Time
    banned   map[string]time.Time
    mu       sync.Mutex
    limit    int
    window   time.Duration
    banTime  time.Duration
}

func NewRateLimiter(limit int, window, banTime time.Duration) *rateLimiter {
    return &rateLimiter{
        requests: make(map[string][]time.Time),
        banned:   make(map[string]time.Time),
        limit:    limit,
        window:   window,
        banTime:  banTime,
    }
}

type BanIPs struct {
    requests    map[string]int
    bannedIPs   map[string]struct{}
    maxRequests int
    mu          sync.Mutex
}

func NewBanIPs(maxRequests int, banTime time.Duration) *BanIPs {
    return &BanIPs{
        requests:    make(map[string]int),
        bannedIPs:   make(map[string]struct{}),
        maxRequests: maxRequests,
    }
}

func (rl *rateLimiter) Allow(ip string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    if bannedUntil, exists := rl.banned[ip]; exists {
        if time.Now().Before(bannedUntil) {
            return false
        }
        delete(rl.banned, ip)
    }

    times := rl.requests[ip]
    var valid []time.Time
    for _, t := range times {
        if time.Now().Sub(t) <= rl.window {
            valid = append(valid, t)
        }
    }
    valid = append(valid, time.Now())
    rl.requests[ip] = valid

    if len(valid) > rl.limit {
        rl.banned[ip] = time.Now().Add(rl.banTime)
        delete(rl.requests, ip)
        return false
    }
    return true
}

func (rb *BanIPs) AllowBanIp(ipB string) bool {
    rb.mu.Lock()
    defer rb.mu.Unlock()

    if _, banned := rb.bannedIPs[ipB]; banned {
        return false
    }

    rb.requests[ipB]++

    if rb.requests[ipB] > rb.maxRequests {
        rb.bannedIPs[ipB] = struct{}{}
        
        alreadyListed := false
        file, err := os.Open("blacklist.txt")
        if err == nil {
            scanner := bufio.NewScanner(file)
            for scanner.Scan() {
                if scanner.Text() == ipB {
                    alreadyListed = true
                    break
                }
            }
            file.Close()
        }

        if !alreadyListed {
            f, err := os.OpenFile("blacklist.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
            if err != nil {
                log.Fatalf("Impossible d'ouvrir le fichier blacklist.txt : %v", err)
            }
            defer f.Close()
            
            if _, err := f.WriteString(ipB + "\n"); err != nil {
                log.Fatalf("Impossible d'écrire dans blacklist.txt : %v", err)
            }
            log.Printf("[BAN] IP %s ajoutée à blacklist.txt", ipB)
        }
        return false
    }
    return true
}



package main

import (
    "bufio"
    "log"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
)

// PatternManager gère le chargement dynamique des patterns
type PatternManager struct {
    patterns    []*regexp.Regexp
    patternPath string
    lastModTime time.Time
    mutex       sync.RWMutex
}

// NewPatternManager crée un nouveau gestionnaire de patterns
func NewPatternManager(path string) *PatternManager {
    pm := &PatternManager{
        patternPath: path,
        patterns:    make([]*regexp.Regexp, 0),
    }
    pm.loadPatterns()
    return pm
}

// loadPatterns charge les patterns depuis le fichier
func (pm *PatternManager) loadPatterns() {
    file, err := os.Open(pm.patternPath)
    if err != nil {
        log.Printf("Erreur lors de l'ouverture du fichier %s: %v", pm.patternPath, err)
        return
    }
    defer file.Close()

    // Récupérer les informations du fichier
    fileInfo, err := file.Stat()
    if err != nil {
        log.Printf("Erreur lors de la récupération des infos du fichier: %v", err)
        return
    }

    pm.mutex.Lock()
    defer pm.mutex.Unlock()

    // Vérifier si le fichier a été modifié
    if !pm.lastModTime.IsZero() && fileInfo.ModTime().Equal(pm.lastModTime) {
        return // Pas de modification
    }

    var newPatterns []*regexp.Regexp
    scanner := bufio.NewScanner(file)
    lineNum := 0

    for scanner.Scan() {
        lineNum++
        line := strings.TrimSpace(scanner.Text())
        
        // Ignorer les lignes vides et les commentaires
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        re, err := regexp.Compile(line)
        if err != nil {
            log.Printf("Erreur de compilation du pattern ligne %d '%s': %v", lineNum, line, err)
            continue
        }
        newPatterns = append(newPatterns, re)
    }

    if err := scanner.Err(); err != nil {
        log.Printf("Erreur lors de la lecture du fichier: %v", err)
        return
    }

    pm.patterns = newPatterns
    pm.lastModTime = fileInfo.ModTime()
    log.Printf("Patterns rechargés: %d patterns chargés depuis %s", len(pm.patterns), pm.patternPath)
}

// checkAndReload vérifie si le fichier a été modifié et recharge si nécessaire
func (pm *PatternManager) checkAndReload() {
    fileInfo, err := os.Stat(pm.patternPath)
    if err != nil {
        log.Printf("Erreur lors de la vérification du fichier: %v", err)
        return
    }

    pm.mutex.RLock()
    needsReload := fileInfo.ModTime().After(pm.lastModTime)
    pm.mutex.RUnlock()

    if needsReload {
        pm.loadPatterns()
    }
}

// StartWatcher démarre la surveillance automatique du fichier
func (pm *PatternManager) StartWatcher(interval time.Duration) {
    ticker := time.NewTicker(interval)
    go func() {
        for range ticker.C {
            pm.checkAndReload()
        }
    }()
    log.Printf("Surveillance du fichier %s démarrée (intervalle: %v)", pm.patternPath, interval)
}

// IsMalicious vérifie si l'input correspond à un pattern malveillant
func (pm *PatternManager) IsMalicious(input string) bool {
    pm.mutex.RLock()
    defer pm.mutex.RUnlock()

    for _, re := range pm.patterns {
        if re.MatchString(input) {
            return true
        }
    }
    return false
}

func LoadPatterns(path string) *PatternManager {
    return NewPatternManager(path)
}

// GetPatternsCount retourne le nombre de patterns chargés
func (pm *PatternManager) GetPatternsCount() int {
    pm.mutex.RLock()
    defer pm.mutex.RUnlock()
    return len(pm.patterns)
}

// ForceReload force le rechargement des patterns
func (pm *PatternManager) ForceReload() {
    pm.loadPatterns()
}


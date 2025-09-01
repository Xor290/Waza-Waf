package main

import (
    "bytes"
    "fmt"
    "gopkg.in/yaml.v3"
    "io/ioutil"
    "log"
    "net/http"
)

type AlertConfig struct {
    WebhookURL string `yaml:"webhook_url"`
	Token	   string `yaml:"token_telegram"`
	ChatID	   string `yaml:"chatid_telegram"`
}

// Lire la config depuis un fichier YAML
func LoadAlertConfig(path string) (*AlertConfig, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var config AlertConfig
    if err := yaml.Unmarshal(data, &config); err != nil {
        return nil, err
    }
    return &config, nil
}

// Envoyer une alerte via webhook
func SendAlert(config *AlertConfig, message string) {
    if config == nil {
        log.Println("[WARN] Aucun config fourni pour les alertes")
        return
    }

    // Webhook Slack
    if config.WebhookURL != "" {
        payload := fmt.Sprintf(`{"text":"%s"}`, message)
        resp, err := http.Post(config.WebhookURL, "application/json", bytes.NewBuffer([]byte(payload)))
        if err != nil {
            log.Printf("[ERROR] Impossible d'envoyer l'alerte webhook: %v", err)
            return
        }
        defer resp.Body.Close()
        log.Printf("[ALERT] Alerte webhook envoyée, statut HTTP: %d", resp.StatusCode)
    }

    // Telegram
    if config.Token != "" && config.ChatID != "" {
        urlTelegram := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.Token)
        payload := fmt.Sprintf(`{"chat_id":"%s","text":"%s"}`, config.ChatID, message)
        resp, err := http.Post(urlTelegram, "application/json", bytes.NewBuffer([]byte(payload)))
        if err != nil {
            log.Printf("[ERROR] Impossible d'envoyer l'alerte Telegram: %v", err)
            return
        }
        defer resp.Body.Close()
        log.Printf("[ALERT] Alerte Telegram envoyée, statut HTTP: %d", resp.StatusCode)
    }

    if config.WebhookURL == "" && (config.Token == "" || config.ChatID == "") {
        log.Println("[WARN] Aucun moyen d'envoyer l'alerte configuré")
    }
}



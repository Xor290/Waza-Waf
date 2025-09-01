#!/bin/bash

LOG_FILE="/var/log/waf.log"
UDP_HOST="192.168.1.100"   # IP du serveur central
UDP_PORT=514               # Port UDP à utiliser

echo "Agent serveur WAF démarré..."

tail -F "$LOG_FILE" | while read line; do
    if [[ "$line" == *"ALERT"* ]]; then
        echo "⚠️  Alerte détectée : $line"
        # Envoi de la ligne en UDP
        echo "$line" | nc -u -w1 $UDP_HOST $UDP_PORT
    fi
done

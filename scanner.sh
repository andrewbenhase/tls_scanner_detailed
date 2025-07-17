#!/bin/bash

# tls_remote_scan.sh
# Scan remote host for TLS/SSL vulnerabilities using Nmap + testssl.sh
# Usage: ./tls_remote_scan.sh <hostname_or_ip> [port]

TARGET="$1"
PORT="${2:-443}"  # Default to HTTPS

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <hostname_or_ip> [port]"
  exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="tls_scan_${TARGET//./_}_${PORT}_$TIMESTAMP.log"

echo "[*] Starting TLS scan of $TARGET:$PORT"
echo "[*] Output will be saved to $LOGFILE"
echo "===================================================" | tee "$LOGFILE"

# --- Nmap TLS scan ---
echo -e "\n[+] Running Nmap SSL enumeration + vulnerability scan..." | tee -a "$LOGFILE"
nmap -Pn -p "$PORT" --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-dh-params "$TARGET" | tee -a "$LOGFILE"

# --- testssl.sh deep scan ---
if ! command -v testssl.sh &>/dev/null; then
  echo -e "\n[!] testssl.sh not found. Install it from https://testssl.sh/" | tee -a "$LOGFILE"
else
  echo -e "\n[+] Running testssl.sh deep TLS scanner..." | tee -a "$LOGFILE"
  testssl.sh --warnings batch "$TARGET:$PORT" | tee -a "$LOGFILE"
fi

echo -e "\n[*] TLS scan complete. Results saved to $LOGFILE"


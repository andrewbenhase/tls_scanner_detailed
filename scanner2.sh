#!/bin/bash

# Usage: ./tls_remote_scan_with_cve_flags.sh <host> [port]
# Requires: nmap, testssl.sh in $PATH

TARGET="$1"
PORT="${2:-443}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="tls_scan_${TARGET//./_}_${PORT}_$TIMESTAMP.log"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <hostname_or_ip> [port]"
  exit 1
fi

echo "[*] Scanning $TARGET:$PORT ..."
echo "[*] Output saved to $LOGFILE"
echo "=== TLS Vulnerability Scan Started: $TIMESTAMP ===" | tee "$LOGFILE"

# --- Nmap scan ---
echo -e "\n[+] Running Nmap TLS scripts..." | tee -a "$LOGFILE"
NMAP_OUT=$(nmap -Pn -p "$PORT" --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-dh-params "$TARGET" 2>/dev/null)
echo "$NMAP_OUT" | tee -a "$LOGFILE"

# --- testssl.sh scan ---
if ! command -v testssl.sh &>/dev/null; then
  echo -e "\n[!] testssl.sh not found. Install it from https://testssl.sh/" | tee -a "$LOGFILE"
  exit 1
fi

echo -e "\n[+] Running testssl.sh..." | tee -a "$LOGFILE"
TESTSSL_OUT=$(testssl.sh --warnings batch "$TARGET:$PORT" 2>/dev/null)
echo "$TESTSSL_OUT" | tee -a "$LOGFILE"

# --- CVE fingerprinting ---
echo -e "\n[+] CVE Fingerprinting..." | tee -a "$LOGFILE"
VULNS=()

# Detect Heartbleed
if echo "$NMAP_OUT" | grep -qi "VULNERABLE:.*Heartbleed"; then
  VULNS+=("CVE-2014-0160: Heartbleed vulnerability detected!")
fi

# Detect support for SSLv2 or SSLv3
if echo "$NMAP_OUT" | grep -q "SSLv2"; then
  VULNS+=("SSLv2 supported — CVE-2016-0703, CVE-2016-0704: DROWN-related")
fi
if echo "$NMAP_OUT" | grep -q "SSLv3"; then
  VULNS+=("SSLv3 supported — CVE-2014-3566: POODLE")
fi

# TLS 1.0 / 1.1
if echo "$NMAP_OUT" | grep -q "TLSv1.0"; then
  VULNS+=("TLSv1.0 enabled — Deprecated. Weak cipher suites likely present.")
fi
if echo "$NMAP_OUT" | grep -q "TLSv1.1"; then
  VULNS+=("TLSv1.1 enabled — Deprecated. Upgrade to TLS 1.2+.")
fi

# Detect weak Diffie-Hellman groups (Logjam)
if echo "$NMAP_OUT" | grep -q "DH group size.*< 2048"; then
  VULNS+=("Weak DH parameters — CVE-2015-4000: Logjam attack possible")
fi

# Parse known OpenSSL versions from cert or banner
DETECTED_VER=$(echo "$TESTSSL_OUT" | grep -iE 'OpenSSL.*[0-9]+\.[0-9]+' | head -n1)
if [[ "$DETECTED_VER" =~ OpenSSL[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+[a-z]?) ]]; then
  VER="${BASH_REMATCH[1]}"
  echo "[*] Detected OpenSSL version: $VER" | tee -a "$LOGFILE"

  # Flag known vulnerable versions (static examples)
  if [[ "$VER" < "1.0.2t" ]]; then
    VULNS+=("OpenSSL $VER — Vulnerable (CVE-2016-0705, CVE-2016-0799, CVE-2014-0160)")
  fi
fi

# --- Report results ---
if [[ ${#VULNS[@]} -eq 0 ]]; then
  echo "[+] No known TLS CVEs flagged from this scan." | tee -a "$LOGFILE"
else
  echo -e "\n[!] Known or likely vulnerabilities detected:" | tee -a "$LOGFILE"
  for v in "${VULNS[@]}"; do
    echo " - $v" | tee -a "$LOGFILE"
  done
fi

echo -e "\n[*] Scan complete. Detailed output in $LOGFILE"


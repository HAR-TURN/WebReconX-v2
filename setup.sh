#!/bin/bash
# WebReconX v2 — Monolithic Auto-Setup Script
set -e

echo "╔═══════════════════════════════════════════════════╗"
echo "║       WebReconX v2 — Enterprise Setup Agent       ║"
echo "╚═══════════════════════════════════════════════════╝"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "[-] Cannot determine Linux distribution. Proceeding with generic fallback..."
    OS="generic"
fi

echo "[*] Detecting OS environment: $OS"
case $OS in
  ubuntu|debian|kali)
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-pip python3-dev \
      nmap libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 \
      libffi-dev libssl-dev libcairo2 libpangocairo-1.0-0 \
      libgdk-pixbuf2.0-0 libxml2-dev libxslt1-dev curl
    ;;
  fedora|centos|rhel)
    sudo dnf install -y python3 python3-pip python3-devel \
      nmap pango harfbuzz libffi-devel openssl-devel cairo \
      libxml2-devel libxslt-devel curl
    ;;
  arch|manjaro)
    sudo pacman -Sy --noconfirm python python-pip nmap \
      pango harfbuzz cairo libffi openssl libxml2 libxslt curl
    ;;
  *)
    echo "[!] Warning: Operational system dependencies may need manual verification."
    ;;
esac

echo "[*] Installing Python ecosystem dependencies..."
pip3 install -r requirements.txt --quiet

echo "[*] Initializing local report storage repositories..."
mkdir -p reports/output

echo "[+] Optimization complete! WebReconX Core Engine is ready."
echo "🚀 Execute: python3 webreconx.py --url https://example.com"

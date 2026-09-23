#!/data/data/com.termux/files/usr/bin/bash

echo "[*] Setting up Mobile Forensic Recovery Engine..."

# 1. Request Android Storage Access
termux-setup-storage

# 2. Update Packages Non-Interactively
export DEBIAN_FRONTEND=noninteractive
pkg update -y -o Dpkg::Options::="--force-confnew"

# 3. Install Required Dependencies
pkg install -y python python-pillow clang make git curl -o Dpkg::Options::="--force-confnew"

# 4. Install Crypto Module for WhatsApp
pip install pycryptodome --quiet

# 5. Create Dedicated Directory & Fetch Latest Script
mkdir -p ~/recovery_app
cd ~/recovery_app

echo "[*] Fetching recovery core from repository..."
curl -s -L "https://raw.githubusercontent.com/KamleshChoudhary7/RecoveryApp/main/recovery_mobile.py" -o recovery_mobile.py

# 6. Execute Application
echo "[+] Initializing Local Dashboard..."
python recovery_mobile.py

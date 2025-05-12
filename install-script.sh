#!/bin/bash

set -e

echo "🔧 Starting OSINT toolkit installation for Kali Linux..."
sleep 1

# --- SYSTEM TOOLS ---
echo "📦 Updating APT and installing OSINT core tools..."
apt update
apt install -y \
    theharvester \
    amass \
    sublist3r \
    dnsrecon \
    libimage-exiftool-perl \
    curl \
    torsocks \
    tor \
    whois \
    python3-pip \
    git \
    make \
    jq

# --- INSTALL pipx (for isolated tool installs) ---
if ! command -v pipx &> /dev/null; then
    echo "📦 Installing pipx..."
    apt install -y pipx
    pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "✅ pipx already installed."
fi

# --- PIPX TOOLS ---
echo "🚀 Installing pipx tools..."

pipx install sherlock || echo "⚠️ sherlock install may already exist."
pipx install maigret || echo "⚠️ maigret install may already exist."
pipx install holehe || echo "⚠️ holehe install may already exist."
pipx install pwned-cli || echo "⚠️ HaveIBeenPwned CLI may already exist."
pipx install socialscan || echo "⚠️ socialscan install may already exist."

# --- TWINT (archived, Git install only) ---
if [ ! -d "twint" ]; then
    echo "⬇️ Cloning TWINT (Twitter scraper)..."
    git clone https://github.com/twintproject/twint.git
    cd twint
    pip3 install . --break-system-packages || echo "⚠️ TWINT may require virtualenv on some Kali builds."
    cd ..
else
    echo "✅ TWINT already cloned."
fi

# --- PhoneInfoga ---
if [ ! -d "phoneinfoga" ]; then
    echo "⬇️ Installing PhoneInfoga..."
    git clone https://github.com/sundowndev/phoneinfoga.git
    cd phoneinfoga
    make install || echo "⚠️ PhoneInfoga make failed, ensure Go & make installed."
    cd ..
else
    echo "✅ PhoneInfoga already cloned."
fi

# --- waybackurls (Go-based) ---
if ! command -v waybackurls &> /dev/null; then
    echo "⬇️ Installing waybackurls (requires Go)..."
    if ! command -v go &> /dev/null; then
        apt install -y golang
    fi
    go install github.com/tomnomnom/waybackurls@latest
    export PATH="$PATH:$(go env GOPATH)/bin"
else
    echo "✅ waybackurls already installed."
fi

# --- FINISH ---
echo -e "\n🎉 OSINT toolkit installation complete."
echo "✔ Tools installed: theHarvester, sherlock, holehe, pwned-cli, socialscan, TWINT, phoneinfoga, sublist3r, amass, dnsrecon, exiftool, waybackurls"

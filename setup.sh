#!/bin/bash

# Offensive Security Toolkit - Setup Script for Linux/Mac
# [!] For authorized security testing only

set -e

echo "[+] Offensive Security Toolkit - Setup"
echo "[!] WARNING: For authorized security testing only"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "[*] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-] Python 3 is not installed. Please install Python 3.8 or higher.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}[-] Python 3.8 or higher is required. Current version: $PYTHON_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Python version $PYTHON_VERSION detected${NC}"

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo -e "${YELLOW}[!] Virtual environment already exists${NC}"
    read -p "Do you want to recreate it? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "[*] Removing existing virtual environment..."
        rm -rf venv
    else
        echo "[*] Using existing virtual environment"
    fi
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment created${NC}"
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install dependencies
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# Create config directory
echo "[*] Creating configuration directory..."
mkdir -p config
mkdir -p logs
mkdir -p output

# Create default config file if it doesn't exist
if [ ! -f "config/config.yaml" ]; then
    echo "[*] Creating default configuration file..."
    cat > config/config.yaml << EOF
# Offensive Security Toolkit Configuration

# Logging settings
logging:
  level: INFO
  file: logs/toolkit.log
  format: "[%(asctime)s] [%(levelname)s] %(message)s"

# Rate limiting (requests per second)
rate_limit:
  enabled: true
  requests_per_second: 10

# Timeout settings (seconds)
timeouts:
  connection: 10
  read: 30

# Output settings
output:
  directory: output
  format: json

# Authorization check
authorization:
  require_confirmation: true
  scope_file: config/authorized_targets.txt
EOF
    echo -e "${GREEN}[+] Default configuration created${NC}"
fi

# Create authorized targets template
if [ ! -f "config/authorized_targets.txt" ]; then
    echo "[*] Creating authorized targets template..."
    cat > config/authorized_targets.txt << EOF
# Authorized Testing Targets
# Add one target per line (IP addresses, domains, or CIDR ranges)
# Example:
# 192.168.1.0/24
# testlab.example.com
# 10.0.0.1

# [!] CRITICAL: Only add targets you have explicit written permission to test
EOF
    echo -e "${GREEN}[+] Authorized targets template created${NC}"
fi

# Check for optional system dependencies
echo ""
echo "[*] Checking optional system dependencies..."

# Check for nmap
if command -v nmap &> /dev/null; then
    echo -e "${GREEN}[+] nmap detected${NC}"
else
    echo -e "${YELLOW}[!] nmap not found (optional but recommended)${NC}"
    echo "    Install with: sudo apt install nmap (Debian/Ubuntu) or brew install nmap (Mac)"
fi

# Check for masscan
if command -v masscan &> /dev/null; then
    echo -e "${GREEN}[+] masscan detected${NC}"
else
    echo -e "${YELLOW}[!] masscan not found (optional)${NC}"
fi

# Check for gobuster
if command -v gobuster &> /dev/null; then
    echo -e "${GREEN}[+] gobuster detected${NC}"
else
    echo -e "${YELLOW}[!] gobuster not found (optional)${NC}"
fi

echo ""
echo -e "${GREEN}[+] Setup completed successfully!${NC}"
echo ""
echo "To activate the virtual environment in the future, run:"
echo "    source venv/bin/activate"
echo ""
echo "To deactivate, run:"
echo "    deactivate"
echo ""
echo -e "${YELLOW}[!] REMINDER: Always obtain written authorization before testing any systems${NC}"

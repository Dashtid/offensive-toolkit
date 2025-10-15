# Offensive Security Toolkit - Setup Script for Windows
# [!] For authorized security testing only

param(
    [switch]$Force
)

Write-Host "[+] Offensive Security Toolkit - Setup" -ForegroundColor Green
Write-Host "[!] WARNING: For authorized security testing only" -ForegroundColor Yellow
Write-Host ""

# Check Python version
Write-Host "[*] Checking Python version..." -ForegroundColor Cyan

try {
    $pythonVersion = & python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
} catch {
    Write-Host "[-] Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "    Please install Python 3.8 or higher from https://www.python.org" -ForegroundColor Red
    exit 1
}

# Extract version number
$versionMatch = $pythonVersion -match "Python (\d+)\.(\d+)\.(\d+)"
$majorVersion = [int]$Matches[1]
$minorVersion = [int]$Matches[2]

if ($majorVersion -lt 3 -or ($majorVersion -eq 3 -and $minorVersion -lt 8)) {
    Write-Host "[-] Python 3.8 or higher is required. Current version: $pythonVersion" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Python version detected: $pythonVersion" -ForegroundColor Green

# Check if virtual environment exists
if (Test-Path "venv") {
    Write-Host "[!] Virtual environment already exists" -ForegroundColor Yellow
    if ($Force) {
        Write-Host "[*] Force flag detected, removing existing virtual environment..." -ForegroundColor Cyan
        Remove-Item -Recurse -Force venv
    } else {
        $response = Read-Host "Do you want to recreate it? (y/n)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Write-Host "[*] Removing existing virtual environment..." -ForegroundColor Cyan
            Remove-Item -Recurse -Force venv
        } else {
            Write-Host "[*] Using existing virtual environment" -ForegroundColor Cyan
        }
    }
}

# Create virtual environment
if (-not (Test-Path "venv")) {
    Write-Host "[*] Creating virtual environment..." -ForegroundColor Cyan
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "[*] Activating virtual environment..." -ForegroundColor Cyan
& ".\venv\Scripts\Activate.ps1"

# Upgrade pip
Write-Host "[*] Upgrading pip..." -ForegroundColor Cyan
python -m pip install --upgrade pip setuptools wheel | Out-Null

# Install dependencies
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Cyan
Write-Host "    This may take several minutes..." -ForegroundColor Yellow
pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Create necessary directories
Write-Host "[*] Creating configuration directories..." -ForegroundColor Cyan
$directories = @("config", "logs", "output")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

# Create default config file
$configFile = "config\config.yaml"
if (-not (Test-Path $configFile)) {
    Write-Host "[*] Creating default configuration file..." -ForegroundColor Cyan

    $configContent = @"
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
"@

    Set-Content -Path $configFile -Value $configContent
    Write-Host "[+] Default configuration created" -ForegroundColor Green
}

# Create authorized targets template
$targetsFile = "config\authorized_targets.txt"
if (-not (Test-Path $targetsFile)) {
    Write-Host "[*] Creating authorized targets template..." -ForegroundColor Cyan

    $targetsContent = @"
# Authorized Testing Targets
# Add one target per line (IP addresses, domains, or CIDR ranges)
# Example:
# 192.168.1.0/24
# testlab.example.com
# 10.0.0.1

# [!] CRITICAL: Only add targets you have explicit written permission to test
"@

    Set-Content -Path $targetsFile -Value $targetsContent
    Write-Host "[+] Authorized targets template created" -ForegroundColor Green
}

# Check for optional tools
Write-Host ""
Write-Host "[*] Checking optional system dependencies..." -ForegroundColor Cyan

# Check for nmap
try {
    $nmapVersion = & nmap --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] nmap detected" -ForegroundColor Green
    }
} catch {
    Write-Host "[!] nmap not found (optional but recommended)" -ForegroundColor Yellow
    Write-Host "    Download from: https://nmap.org/download.html" -ForegroundColor Gray
}

# Check for Wireshark (tshark)
try {
    $tsharkVersion = & tshark --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Wireshark (tshark) detected" -ForegroundColor Green
    }
} catch {
    Write-Host "[!] Wireshark not found (optional)" -ForegroundColor Yellow
    Write-Host "    Download from: https://www.wireshark.org/download.html" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[+] Setup completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "To activate the virtual environment in the future, run:" -ForegroundColor Cyan
Write-Host "    .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host ""
Write-Host "To deactivate, run:" -ForegroundColor Cyan
Write-Host "    deactivate" -ForegroundColor White
Write-Host ""
Write-Host "[!] REMINDER: Always obtain written authorization before testing any systems" -ForegroundColor Yellow
Write-Host ""
Write-Host "Note: If you encounter execution policy errors, run:" -ForegroundColor Gray
Write-Host "    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process" -ForegroundColor Gray

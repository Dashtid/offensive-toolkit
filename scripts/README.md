# Scripts Directory

Setup and dependency management scripts for the Offensive Security Toolkit.

## Files

### Requirements
- **requirements.txt** - Production dependencies
- **requirements-dev.txt** - Development and testing dependencies

**Note**: These files are also copied to the project root for pip/uv compatibility.

### Setup Scripts
- **setup.sh** - Linux/macOS setup script
- **setup.ps1** - Windows PowerShell setup script

## Usage

### Linux/macOS
```bash
./scripts/setup.sh
```

### Windows
```powershell
.\scripts\setup.ps1
```

### Installing Dependencies
```bash
# Using UV (recommended)
uv venv --python 3.14
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
uv pip install -r requirements.txt
uv pip install -r requirements-dev.txt

# Using pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

#!/bin/bash

# ╔═══════════════════════════════════════════════════════════╗
# ║           ReconnV2 - Kali Linux Installer                 ║
# ╚═══════════════════════════════════════════════════════════╝

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
cd "$PROJECT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
 ____                            __     ______  
|  _ \ ___  ___ ___  _ __  _ __  \ \   / /___ \ 
| |_) / _ \/ __/ _ \| '_ \| '_ \  \ \ / /  __) |
|  _ <  __/ (_| (_) | | | | | | |  \ V /  / __/ 
|_| \_\___|\___\___/|_| |_|_| |_|   \_/  |_____|
                                                 
         Advanced Reconnaissance Pipeline
EOF
echo -e "${NC}"

echo -e "${BLUE}[*] Starting installation for Kali Linux...${NC}
"

# Check if running as root for system packages
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[!] Not running as root. Some features may require sudo.${NC}"
        SUDO="sudo"
    else
        SUDO=""
    fi
}

# Check Python version
check_python() {
    echo -e "${BLUE}[*] Checking Python version...${NC}"
    if command -v python3 &> /dev/null; then
        PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        echo -e "${GREEN}[✓] Python $PY_VERSION found${NC}"
        
        # Keep installer aligned with pyproject requires-python.
        if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 12) else 1)'; then
            echo -e "${GREEN}[✓] Python version is compatible${NC}"
        else
            echo -e "${RED}[✗] Python 3.12+ required. Current: $PY_VERSION${NC}"
            exit 1
        fi
    else
        echo -e "${RED}[✗] Python3 not found. Please install Python 3.12+${NC}"
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    echo -e "
${BLUE}[*] Installing system dependencies...${NC}"
    
    $SUDO apt update -qq
    
    # Core tools
    TOOLS=(
        "subfinder"
        "amass"
        "nuclei"
        "golang-go"
        "chromium"
    )
    
    for tool in "${TOOLS[@]}"; do
        if command -v ${tool%%-*} &> /dev/null || dpkg -l | grep -q "^ii  $tool"; then
            echo -e "${GREEN}[✓] $tool already installed${NC}"
        else
            echo -e "${YELLOW}[*] Installing $tool...${NC}"
            $SUDO apt install -y $tool 2>/dev/null || echo -e "${YELLOW}[!] $tool not in apt, will try alternative${NC}"
        fi
    done
}

# Install Go tools
install_go_tools() {
    echo -e "
${BLUE}[*] Installing Go-based tools...${NC}"
    
    # Set Go path
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    # waybackurls
    if command -v waybackurls &> /dev/null; then
        echo -e "${GREEN}[✓] waybackurls already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing waybackurls...${NC}"
        go install github.com/tomnomnom/waybackurls@latest || echo -e "${YELLOW}[!] Failed to install waybackurls${NC}"
    fi
    
    # gau
    if command -v gau &> /dev/null; then
        echo -e "${GREEN}[✓] gau already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing gau...${NC}"
        go install github.com/lc/gau/v2/cmd/gau@latest || echo -e "${YELLOW}[!] Failed to install gau${NC}"
    fi
}

# Create virtual environment and install Python deps
install_python_deps() {
    echo -e "
${BLUE}[*] Setting up Python environment...${NC}"
    
    # Create venv if not exists
    if [ ! -d ".venv" ]; then
        echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
        python3 -m venv .venv
    fi
    
    # Activate venv
    source .venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip -q
    
    # Install package
    echo -e "${YELLOW}[*] Installing ReconnV2...${NC}"
    pip install -e "." -q

    # Install optional dependencies
    pip install dnspython playwright -q || echo -e "${YELLOW}[!] Failed to install optional python packages${NC}"
    
    echo -e "${GREEN}[✓] Python dependencies installed${NC}"
}

# Setup directories
setup_directories() {
    echo -e "
${BLUE}[*] Setting up directories...${NC}"
    
    mkdir -p jobs/{queued,running,finished,failed}
    mkdir -p config
    mkdir -p archive
    
    # Create resolvers if not exists
    if [ ! -f "config/resolvers.txt" ]; then
        cat > config/resolvers.txt << 'RESOLVERS'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
208.67.222.222
208.67.220.220
RESOLVERS
    fi
    
    echo -e "${GREEN}[✓] Directories created${NC}"
}

# Create shell aliases
create_aliases() {
    echo -e "
${BLUE}[*] Creating shell aliases...${NC}"
    
    ALIAS_FILE="$HOME/.recon_aliases"
    
    cat > "$ALIAS_FILE" << ALIASES
# ReconnV2 Aliases
RECONN_HOME="$PROJECT_DIR"
alias recon='cd "$RECONN_HOME" && source .venv/bin/activate && recon-cli'
alias recon-scan='recon scan'
alias recon-quick='recon scan --profile quick --inline'
alias recon-full='recon scan --profile full --inline'
alias recon-passive='recon scan --profile passive --inline'
alias recon-jobs='recon list-jobs'
alias recon-status='recon status'

# Quick functions
quick-recon() {
    cd "$RECONN_HOME" && source .venv/bin/activate
    recon-cli scan "$1" --profile passive --inline
}

deep-recon() {
    cd "$RECONN_HOME" && source .venv/bin/activate
    recon-cli scan "$1" --profile deep --scanner nuclei --inline
}
ALIASES

    # Add to bashrc if not already there
    if ! grep -q "recon_aliases" ~/.bashrc 2>/dev/null; then
        echo "" >> ~/.bashrc
        echo "# ReconnV2 aliases" >> ~/.bashrc
        echo "[ -f $ALIAS_FILE ] && source $ALIAS_FILE" >> ~/.bashrc
    fi
    
    # Add to zshrc if exists
    if [ -f ~/.zshrc ] && ! grep -q "recon_aliases" ~/.zshrc; then
        echo "" >> ~/.zshrc
        echo "# ReconnV2 aliases" >> ~/.zshrc
        echo "[ -f $ALIAS_FILE ] && source $ALIAS_FILE" >> ~/.zshrc
    fi
    
    echo -e "${GREEN}[✓] Aliases created. Run 'source ~/.bashrc' to activate${NC}"
}

# Create wrapper script
create_wrapper() {
    echo -e "
${BLUE}[*] Creating global wrapper...${NC}"
    
    WRAPPER="/usr/local/bin/recon-cli"
    
    $SUDO tee $WRAPPER > /dev/null << WRAPPER
#!/bin/bash
cd "$PROJECT_DIR" 2>/dev/null || exit 1
source .venv/bin/activate 2>/dev/null
export PYTHONPATH="$PROJECT_DIR"
exec python -m recon_cli "$@"
WRAPPER

    $SUDO chmod +x $WRAPPER
    echo -e "${GREEN}[✓] Wrapper created at $WRAPPER${NC}"
}

# Verify installation
verify_installation() {
    echo -e "
${BLUE}[*] Verifying installation...${NC}"
    
    source .venv/bin/activate
    
    echo -e "
${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}         Installation Summary           ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}
"
    
    # Check tools
    tools=("subfinder" "amass" "nuclei" "waybackurls")
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            echo -e "${GREEN}[✓] $tool${NC}"
        else
            echo -e "${YELLOW}[!] $tool (not found - optional)${NC}"
        fi
    done
    
    echo ""
    
    # Test recon-cli
    if [ -x ".venv/bin/recon-cli" ]; then
        echo -e "${GREEN}[✓] recon-cli working${NC}"
    else
        echo -e "${RED}[✗] recon-cli has issues${NC}"
    fi
}

# Print usage
print_usage() {
    echo -e "
${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}           Quick Start Guide            ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}
"
    
    echo -e "${GREEN}Activate environment:${NC}"
    echo -e "  source .venv/bin/activate
"
    
    echo -e "${GREEN}Basic scan:${NC}"
    echo -e "  recon-cli scan target.com --inline
"
    
    echo -e "${GREEN}Full scan with nuclei:${NC}"
    echo -e "  recon-cli scan target.com --profile full --scanner nuclei --inline
"
    
    echo -e "${GREEN}View help:${NC}"
    echo -e "  recon-cli --help
"
    
    echo -e "${GREEN}After restarting terminal, use shortcuts:${NC}"
    echo -e "  quick-recon target.com"
    echo -e "  deep-recon target.com
"
}

# Main
main() {
    check_root
    check_python
    install_system_deps
    install_go_tools
    install_python_deps
    setup_directories
    create_aliases
    # create_wrapper  # Uncomment if you want global install
    verify_installation
    print_usage
    
    echo -e "
${GREEN}[✓] Installation complete!${NC}
"
}

main "$@"

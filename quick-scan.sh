#!/bin/bash

# ╔═══════════════════════════════════════════════════════════╗
# ║              ReconnV2 - Quick Scan Script                 ║
# ╚═══════════════════════════════════════════════════════════╝

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Banner
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
 ____                            __     ______  
|  _ \ ___  ___ ___  _ __  _ __  \ \   / /___ \ 
| |_) / _ \/ __/ _ \| '_ \| '_ \  \ \ / /  __) |
|  _ <  __/ (_| (_) | | | | | | |  \ V /  / __/ 
|_| \_\___|\___\___/|_| |_|_| |_|   \_/  |_____|
                                                 
         Quick Reconnaissance Scanner
EOF
    echo -e "${NC}"
}

# Help
show_help() {
    echo -e "${CYAN}Usage:${NC}"
    echo -e "  ./quick-scan.sh <target> [options]"
    echo ""
    echo -e "${CYAN}Options:${NC}"
    echo -e "  -p, --profile    Scan profile: passive, full, quick, deep (default: passive)"
    echo -e "  -s, --scanner    Use scanner: nuclei, wpscan"
    echo -e "  -a, --active     Active module: js-secrets, backup, cors"
    echo -e "  -f, --file       Targets file for multiple targets"
    echo -e "  -o, --output     Output directory"
    echo -e "  -h, --help       Show this help"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo -e "  ./quick-scan.sh example.com"
    echo -e "  ./quick-scan.sh example.com -p full -s nuclei"
    echo -e "  ./quick-scan.sh -f targets.txt -p deep"
    echo ""
}

# Activate venv
activate_venv() {
    if [ -d ".venv" ]; then
        source .venv/bin/activate
    else
        echo -e "${RED}[!] Virtual environment not found. Run install.sh first.${NC}"
        exit 1
    fi
}

# Parse arguments
parse_args() {
    TARGET=""
    PROFILE="passive"
    SCANNER=""
    ACTIVE_MODULES=()
    TARGETS_FILE=""
    OUTPUT_DIR=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--profile)
                PROFILE="$2"
                shift 2
                ;;
            -s|--scanner)
                SCANNER="$2"
                shift 2
                ;;
            -a|--active)
                ACTIVE_MODULES+=("$2")
                shift 2
                ;;
            -f|--file)
                TARGETS_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done
    
    # Validate
    if [ -z "$TARGET" ] && [ -z "$TARGETS_FILE" ]; then
        echo -e "${RED}[!] Error: Target or targets file required${NC}"
        show_help
        exit 1
    fi
}

# Build command
build_command() {
    CMD="python -m recon_cli scan"
    
    if [ -n "$TARGET" ]; then
        CMD="$CMD $TARGET"
    fi
    
    if [ -n "$TARGETS_FILE" ]; then
        CMD="$CMD --targets-file $TARGETS_FILE"
    fi
    
    CMD="$CMD --profile $PROFILE"
    
    if [ -n "$SCANNER" ]; then
        CMD="$CMD --scanner $SCANNER"
    fi
    
    for module in "${ACTIVE_MODULES[@]}"; do
        CMD="$CMD --active-module $module"
    done
    
    CMD="$CMD --inline"
    
    echo "$CMD"
}

# Run scan
run_scan() {
    echo -e "${BLUE}[*] Starting scan...${NC}"
    echo -e "${YELLOW}[*] Target: ${TARGET:-$TARGETS_FILE}${NC}"
    echo -e "${YELLOW}[*] Profile: $PROFILE${NC}"
    
    if [ -n "$SCANNER" ]; then
        echo -e "${YELLOW}[*] Scanner: $SCANNER${NC}"
    fi
    
    echo ""
    
    CMD=$(build_command)
    echo -e "${CYAN}[>] $CMD${NC}\n"
    
    eval $CMD
    
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "\n${GREEN}[✓] Scan completed successfully!${NC}"
        echo -e "${BLUE}[*] Results saved in jobs/finished/${NC}"
    else
        echo -e "\n${RED}[✗] Scan failed with exit code $EXIT_CODE${NC}"
    fi
}

# Main
main() {
    show_banner
    parse_args "$@"
    activate_venv
    run_scan
}

main "$@"

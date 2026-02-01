#!/bin/bash

# ╔═══════════════════════════════════════════════════════════╗
# ║           ReconnV2 - Interactive Scanner                  ║
# ╚═══════════════════════════════════════════════════════════╝

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Activate venv
if [ -d ".venv" ]; then
    source .venv/bin/activate 2>/dev/null
fi

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗            ║
    ║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║            ║
    ║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║            ║
    ║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║            ║
    ║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║            ║
    ║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ V2        ║
    ║                                                           ║
    ║           Advanced Reconnaissance Pipeline                ║
    ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Main menu
main_menu() {
    echo -e "${WHITE}╔═══════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║          القائمة الرئيسية             ║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[1]${NC} 🔍 فحص سريع (Quick Scan)          ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[2]${NC} 🎯 فحص سلبي (Passive Scan)        ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[3]${NC} 🚀 فحص شامل (Full Scan)           ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[4]${NC} 🔬 فحص عميق (Deep Scan)           ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[5]${NC} 🐛 فحص Bug Bounty                 ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[6]${NC} 🕵️  فحص خفي (Stealth)              ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[7]${NC} 📱 فحص API فقط                    ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[8]${NC} 🔧 فحص WordPress                  ${WHITE}║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} ${YELLOW}[9]${NC} 📋 عرض المهام                      ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${YELLOW}[10]${NC} 📊 حالة مهمة                      ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${YELLOW}[11]${NC} 📄 تصدير النتائج                  ${WHITE}║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} ${CYAN}[12]${NC} ⚙️  فحص النظام (Doctor)            ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${CYAN}[13]${NC} 🗑️  تنظيف المهام القديمة            ${WHITE}║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} ${RED}[0]${NC}  ❌ خروج                           ${WHITE}║${NC}"
    echo -e "${WHITE}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${MAGENTA}اختر: ${NC}"
}

# Get target from user
get_target() {
    echo ""
    echo -ne "${CYAN}أدخل الهدف (domain/IP): ${NC}"
    read TARGET
    
    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] الهدف مطلوب${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[✓] الهدف: $TARGET${NC}"
    return 0
}

# Get targets file
get_targets_file() {
    echo ""
    echo -ne "${CYAN}أدخل مسار ملف الأهداف (أو اضغط Enter للهدف الواحد): ${NC}"
    read TARGETS_FILE
    
    if [ -n "$TARGETS_FILE" ] && [ -f "$TARGETS_FILE" ]; then
        echo -e "${GREEN}[✓] ملف الأهداف: $TARGETS_FILE${NC}"
        return 0
    elif [ -n "$TARGETS_FILE" ]; then
        echo -e "${RED}[!] الملف غير موجود${NC}"
        return 1
    fi
    
    return 0
}

# Run scan with options
run_scan() {
    local profile=$1
    local extra_opts=$2
    
    get_target
    if [ $? -ne 0 ]; then
        return
    fi
    
    echo ""
    echo -e "${BLUE}[*] جاري بدء الفحص...${NC}"
    echo -e "${YELLOW}[*] الملف الشخصي: $profile${NC}"
    echo ""
    
    CMD="python -m recon_cli scan $TARGET --profile $profile --inline $extra_opts"
    echo -e "${CYAN}> $CMD${NC}"
    echo ""
    
    eval $CMD
    
    echo ""
    echo -e "${GREEN}[✓] انتهى الفحص${NC}"
    echo -ne "${YELLOW}اضغط Enter للمتابعة...${NC}"
    read
}

# List jobs
list_jobs() {
    echo ""
    echo -e "${BLUE}[*] المهام:${NC}"
    echo ""
    python -m recon_cli list-jobs
    echo ""
    echo -ne "${YELLOW}اضغط Enter للمتابعة...${NC}"
    read
}

# Show job status
job_status() {
    echo ""
    echo -ne "${CYAN}أدخل رقم المهمة: ${NC}"
    read JOB_ID
    
    if [ -z "$JOB_ID" ]; then
        echo -e "${RED}[!] رقم المهمة مطلوب${NC}"
        return
    fi
    
    python -m recon_cli status "$JOB_ID"
    echo ""
    echo -ne "${YELLOW}اضغط Enter للمتابعة...${NC}"
    read
}

# Export results
export_results() {
    echo ""
    echo -ne "${CYAN}أدخل رقم المهمة: ${NC}"
    read JOB_ID
    
    if [ -z "$JOB_ID" ]; then
        echo -e "${RED}[!] رقم المهمة مطلوب${NC}"
        return
    fi
    
    echo -e "${BLUE}[*] التصدير...${NC}"
    python -m recon_cli export "$JOB_ID"
    echo ""
    echo -ne "${YELLOW}اضغط Enter للمتابعة...${NC}"
    read
}

# Doctor check
run_doctor() {
    echo ""
    echo -e "${BLUE}[*] فحص النظام...${NC}"
    echo ""
    python -m recon_cli doctor
    echo ""
    echo -ne "${YELLOW}اضغط Enter للمتابعة...${NC}"
    read
}

# Prune old jobs
prune_jobs() {
    echo ""
    echo -ne "${CYAN}حذف المهام الأقدم من كم يوم؟ [7]: ${NC}"
    read DAYS
    DAYS=${DAYS:-7}
    
    echo -e "${BLUE}[*] تنظيف المهام...${NC}"
    python -m recon_cli prune --days $DAYS
    echo ""
    echo -ne "${YELLOW}اضغط Enter للمتابعة...${NC}"
    read
}

# Main loop
main() {
    while true; do
        show_banner
        main_menu
        read choice
        
        case $choice in
            1) run_scan "quick" "" ;;
            2) run_scan "passive" "" ;;
            3) run_scan "full" "" ;;
            4) run_scan "deep" "--scanner nuclei" ;;
            5) run_scan "bugbounty" "--scanner nuclei --active-module js-secrets --active-module backup" ;;
            6) run_scan "stealth" "" ;;
            7) run_scan "api-only" "" ;;
            8) run_scan "wordpress" "--scanner wpscan" ;;
            9) list_jobs ;;
            10) job_status ;;
            11) export_results ;;
            12) run_doctor ;;
            13) prune_jobs ;;
            0|q|Q)
                echo -e "\n${GREEN}مع السلامة! 👋${NC}\n"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] خيار غير صالح${NC}"
                sleep 1
                ;;
        esac
    done
}

# Run
main

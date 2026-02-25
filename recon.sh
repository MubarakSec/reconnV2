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

# Resolve Python executable
if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
else
    echo -e "${RED}[!] Python غير متوفر. ثبّت Python 3 أولاً.${NC}"
    exit 1
fi

pause_screen() {
    echo ""
    echo -ne "${YELLOW}اضغط Enter للمتابعة...${NC}"
    read -r
}

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
    echo -e "${WHITE}╔═══════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║               القائمة الرئيسية                ║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[1]${NC}  🔍 فحص سريع (Quick Scan)            ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[2]${NC}  🎯 فحص سلبي (Passive Scan)          ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[3]${NC}  🚀 فحص شامل (Full Scan)             ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[4]${NC}  🔬 فحص عميق (Deep Scan)             ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[5]${NC}  🐛 فحص Bug Bounty                  ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[6]${NC}  🕵️  فحص خفي (Stealth)               ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[7]${NC}  📱 فحص API فقط                      ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${GREEN}[8]${NC}  🔧 فحص WordPress                    ${WHITE}║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} ${YELLOW}[9]${NC}  📋 عرض المهام                        ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${YELLOW}[10]${NC} 📊 حالة مهمة                        ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${YELLOW}[11]${NC} 📄 تصدير النتائج                    ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${YELLOW}[12]${NC} 🧾 توليد تقرير                      ${WHITE}║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} ${CYAN}[13]${NC} ⚙️  فحص النظام (Doctor)              ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${CYAN}[14]${NC} 🗑️  تنظيف المهام القديمة              ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${CYAN}[15]${NC} 🧙 معالج الإعداد (Wizard)             ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${CYAN}[16]${NC} 🖥️  الوضع التفاعلي (Interactive)      ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${CYAN}[17]${NC} 🧩 إعداد الإكمال التلقائي             ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} ${CYAN}[18]${NC} 🧱 عرض Schema JSON                  ${WHITE}║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} ${RED}[0]${NC}  ❌ خروج                             ${WHITE}║${NC}"
    echo -e "${WHITE}╚═══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${MAGENTA}اختر: ${NC}"
}

# Extract host from input (URL, host:port, or host/path)
extract_host() {
    local value="$1"
    local host="$value"
    if [[ "$host" == *"://"* ]]; then
        host="${host#*://}"
    fi
    host="${host%%/*}"
    host="${host%%\?*}"
    host="${host%%#*}"
    host="${host##*@}"
    if [[ "$host" == \[*\] ]]; then
        host="${host#[}"
        host="${host%]}"
    else
        host="${host%%:*}"
    fi
    echo "$host"
}

# Check IPv4
is_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for o in "$o1" "$o2" "$o3" "$o4"; do
        if [ "$o" -gt 255 ] 2>/dev/null || [ "$o" -lt 0 ] 2>/dev/null; then
            return 1
        fi
    done
    return 0
}

# Get target or targets file
get_targets() {
    TARGET=""
    TARGETS_FILE=""
    echo ""
    echo -ne "${CYAN}أدخل الهدف (domain/IP/URL) أو ملف الأهداف: ${NC}"
    read INPUT

    if [ -z "$INPUT" ]; then
        echo -e "${RED}[!] الهدف مطلوب${NC}"
        return 1
    fi

    if [ -f "$INPUT" ]; then
        TARGETS_FILE="$INPUT"
        echo -e "${GREEN}[✓] ملف الأهداف: $TARGETS_FILE${NC}"
    else
        TARGET="$INPUT"
        echo -e "${GREEN}[✓] الهدف: $TARGET${NC}"
    fi
    return 0
}

# Detect if targets file contains any IPs
file_has_ip() {
    local file="$1"
    local line host
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line%%[[:space:]]*}"
        [ -z "$line" ] && continue
        host="$(extract_host "$line")"
        if is_ipv4 "$host"; then
            return 0
        fi
    done < "$file"
    return 1
}

# Run scan with options
run_scan() {
    local profile="$1"
    shift
    local extra_args=("$@")

    get_targets
    if [ $? -ne 0 ]; then
        return
    fi

    local allow_ip_flag=""
    local split_flag=()
    local target_args=()
    if [ -n "$TARGETS_FILE" ]; then
        target_args+=(--targets-file "$TARGETS_FILE")
        if file_has_ip "$TARGETS_FILE"; then
            allow_ip_flag="--allow-ip"
        fi
        echo -ne "${CYAN}تقسيم الأهداف إلى مهام منفصلة؟ [y/N]: ${NC}"
        read SPLIT_TARGETS
        if [[ "$SPLIT_TARGETS" =~ ^[Yy]$ ]]; then
            split_flag+=(--split-targets)
        fi
    else
        target_args+=("$TARGET")
        host="$(extract_host "$TARGET")"
        if is_ipv4 "$host"; then
            allow_ip_flag="--allow-ip"
        fi
    fi

    prompt_auth

    echo ""
    echo -e "${BLUE}[*] جاري بدء الفحص...${NC}"
    echo -e "${YELLOW}[*] الملف الشخصي: $profile${NC}"
    if [ "$AUTH_ENABLED" = "1" ]; then
        echo -e "${YELLOW}[*] المصادقة: مفعلة (مخفية)${NC}"
    fi
    echo ""

    CMD=("$PYTHON_BIN" -m recon_cli scan "${target_args[@]}" --profile "$profile" --inline)
    if [ -n "$allow_ip_flag" ]; then
        CMD+=("$allow_ip_flag")
    fi
    CMD+=("${split_flag[@]}" "${extra_args[@]}")

    echo -e "${CYAN}> ${CMD[*]}${NC}"
    echo ""

    if [ ${#AUTH_ENV[@]} -gt 0 ]; then
        env "${AUTH_ENV[@]}" "${CMD[@]}"
    else
        "${CMD[@]}"
    fi

    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}[✓] انتهى الفحص بنجاح${NC}"
    else
        echo ""
        echo -e "${RED}[!] فشل تنفيذ الفحص${NC}"
    fi
    pause_screen
}

# Prompt for auth settings
prompt_auth() {
    AUTH_ENV=()
    AUTH_ENABLED="0"

    echo ""
    echo -ne "${CYAN}تفعيل المصادقة لهذا الفحص؟ [y/N]: ${NC}"
    read -r USE_AUTH
    if [[ ! "$USE_AUTH" =~ ^[Yy]$ ]]; then
        return
    fi

    echo ""
    echo -e "${WHITE}اختر نوع المصادقة:${NC}"
    echo -e "${WHITE}[1]${NC} Bearer Token"
    echo -e "${WHITE}[2]${NC} Headers (key: value; ...)"
    echo -e "${WHITE}[3]${NC} Cookies (key=value; ...)"
    echo -e "${WHITE}[4]${NC} Login Flow (URL + payload)"
    echo -ne "${MAGENTA}اختيارك: ${NC}"
    read -r AUTH_CHOICE

    AUTH_ENV+=("RECON_ENABLE_AUTH_SCAN=1")
    AUTH_ENABLED="1"

    case "$AUTH_CHOICE" in
        1)
            echo -ne "${CYAN}أدخل Bearer Token: ${NC}"
            read -r AUTH_TOKEN
            if [ -n "$AUTH_TOKEN" ]; then
                AUTH_ENV+=("RECON_AUTH_BEARER=$AUTH_TOKEN")
            fi
            ;;
        2)
            echo -ne "${CYAN}أدخل Headers (مثال: Authorization: Bearer X; X-API-Key: Y): ${NC}"
            read -r AUTH_HEADERS
            if [ -n "$AUTH_HEADERS" ]; then
                AUTH_ENV+=("RECON_AUTH_HEADERS=$AUTH_HEADERS")
            fi
            ;;
        3)
            echo -ne "${CYAN}أدخل Cookies (مثال: session=abc; csrftoken=xyz): ${NC}"
            read -r AUTH_COOKIES
            if [ -n "$AUTH_COOKIES" ]; then
                AUTH_ENV+=("RECON_AUTH_COOKIES=$AUTH_COOKIES")
            fi
            ;;
        4)
            echo -ne "${CYAN}أدخل Login URL (مثال: https://target.com/login): ${NC}"
            read -r AUTH_LOGIN_URL
            if [ -n "$AUTH_LOGIN_URL" ]; then
                AUTH_ENV+=("RECON_AUTH_LOGIN_URL=$AUTH_LOGIN_URL")
            fi
            echo -ne "${CYAN}HTTP Method [POST]: ${NC}"
            read -r AUTH_LOGIN_METHOD
            AUTH_LOGIN_METHOD=${AUTH_LOGIN_METHOD:-POST}
            AUTH_ENV+=("RECON_AUTH_LOGIN_METHOD=$AUTH_LOGIN_METHOD")

            echo -ne "${CYAN}Payload (form أو JSON): ${NC}"
            read -r AUTH_LOGIN_PAYLOAD
            if [ -n "$AUTH_LOGIN_PAYLOAD" ]; then
                AUTH_ENV+=("RECON_AUTH_LOGIN_PAYLOAD=$AUTH_LOGIN_PAYLOAD")
            fi

            echo -ne "${CYAN}Content-Type [application/x-www-form-urlencoded]: ${NC}"
            read -r AUTH_CONTENT_TYPE
            AUTH_CONTENT_TYPE=${AUTH_CONTENT_TYPE:-application/x-www-form-urlencoded}
            AUTH_ENV+=("RECON_AUTH_LOGIN_CONTENT_TYPE=$AUTH_CONTENT_TYPE")

            echo -ne "${CYAN}Success Regex (اختياري): ${NC}"
            read -r AUTH_SUCCESS_RE
            if [ -n "$AUTH_SUCCESS_RE" ]; then
                AUTH_ENV+=("RECON_AUTH_LOGIN_SUCCESS_REGEX=$AUTH_SUCCESS_RE")
            fi

            echo -ne "${CYAN}Fail Regex (اختياري): ${NC}"
            read -r AUTH_FAIL_RE
            if [ -n "$AUTH_FAIL_RE" ]; then
                AUTH_ENV+=("RECON_AUTH_LOGIN_FAIL_REGEX=$AUTH_FAIL_RE")
            fi

            echo -ne "${CYAN}Cookie Names (اختياري, مفصولة بفواصل): ${NC}"
            read -r AUTH_COOKIE_NAMES
            if [ -n "$AUTH_COOKIE_NAMES" ]; then
                AUTH_ENV+=("RECON_AUTH_LOGIN_COOKIE_NAMES=$AUTH_COOKIE_NAMES")
            fi

            echo -ne "${CYAN}Login Headers (اختياري): ${NC}"
            read -r AUTH_LOGIN_HEADERS
            if [ -n "$AUTH_LOGIN_HEADERS" ]; then
                AUTH_ENV+=("RECON_AUTH_LOGIN_HEADERS=$AUTH_LOGIN_HEADERS")
            fi
            ;;
        *)
            AUTH_ENV=()
            AUTH_ENABLED="0"
            ;;
    esac
}

# List jobs
list_jobs() {
    echo ""
    echo -e "${BLUE}[*] المهام:${NC}"
    echo ""
    "$PYTHON_BIN" -m recon_cli list-jobs
    pause_screen
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
    
    "$PYTHON_BIN" -m recon_cli status "$JOB_ID"
    pause_screen
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
    
    echo -ne "${CYAN}صيغة التصدير [jsonl|txt|zip] (الافتراضي: jsonl): ${NC}"
    read -r EXPORT_FORMAT
    EXPORT_FORMAT=${EXPORT_FORMAT:-jsonl}

    echo -e "${BLUE}[*] التصدير...${NC}"
    "$PYTHON_BIN" -m recon_cli export "$JOB_ID" --format "$EXPORT_FORMAT"
    pause_screen
}

# Generate report
generate_report() {
    echo ""
    echo -ne "${CYAN}أدخل رقم المهمة: ${NC}"
    read -r JOB_ID
    if [ -z "$JOB_ID" ]; then
        echo -e "${RED}[!] رقم المهمة مطلوب${NC}"
        return
    fi

    echo -ne "${CYAN}صيغة التقرير [html|json|csv|markdown|xml|pdf] (الافتراضي: html): ${NC}"
    read -r REPORT_FORMAT
    REPORT_FORMAT=${REPORT_FORMAT:-html}

    "$PYTHON_BIN" -m recon_cli report "$JOB_ID" --format "$REPORT_FORMAT"
    pause_screen
}

# Doctor check
run_doctor() {
    echo ""
    echo -e "${BLUE}[*] فحص النظام...${NC}"
    echo ""
    "$PYTHON_BIN" -m recon_cli doctor
    pause_screen
}

# Prune old jobs
prune_jobs() {
    echo ""
    echo -ne "${CYAN}حذف المهام الأقدم من كم يوم؟ [7]: ${NC}"
    read DAYS
    DAYS=${DAYS:-7}
    
    echo -e "${BLUE}[*] تنظيف المهام...${NC}"
    "$PYTHON_BIN" -m recon_cli prune --days "$DAYS"
    pause_screen
}

run_wizard() {
    echo ""
    "$PYTHON_BIN" -m recon_cli wizard
    pause_screen
}

run_interactive() {
    echo ""
    "$PYTHON_BIN" -m recon_cli interactive
    pause_screen
}

setup_completions() {
    echo ""
    echo -ne "${CYAN}الشل [bash|zsh|fish|powershell] (الافتراضي: bash): ${NC}"
    read -r SHELL_NAME
    SHELL_NAME=${SHELL_NAME:-bash}

    echo -ne "${CYAN}تثبيت الإكمال تلقائيًا؟ [y/N]: ${NC}"
    read -r INSTALL_COMPLETIONS
    if [[ "$INSTALL_COMPLETIONS" =~ ^[Yy]$ ]]; then
        "$PYTHON_BIN" -m recon_cli completions --shell "$SHELL_NAME" --install
    else
        "$PYTHON_BIN" -m recon_cli completions --shell "$SHELL_NAME"
    fi
    pause_screen
}

show_schema() {
    echo ""
    "$PYTHON_BIN" -m recon_cli schema --format json
    pause_screen
}

# Main loop
main() {
    while true; do
        show_banner
        main_menu
        read choice
        
        case $choice in
            1) run_scan "quick" ;;
            2) run_scan "passive" ;;
            3) run_scan "full" ;;
            4) run_scan "deep" ;;
            5) run_scan "bugbounty" --active-module js-secrets --active-module backup ;;
            6) run_scan "stealth" ;;
            7) run_scan "api-only" ;;
            8) run_scan "wordpress" --scanner wpscan ;;
            9) list_jobs ;;
            10) job_status ;;
            11) export_results ;;
            12) generate_report ;;
            13) run_doctor ;;
            14) prune_jobs ;;
            15) run_wizard ;;
            16) run_interactive ;;
            17) setup_completions ;;
            18) show_schema ;;
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

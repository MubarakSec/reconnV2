#!/usr/bin/env bash

# ReconnV2 interactive wrapper for recon_cli.
# Keeps menu UX in sync with current CLI commands/options.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
else
    echo -e "${RED}[!] Python is not available. Install Python 3 first.${NC}"
    exit 1
fi

if [ -d "$SCRIPT_DIR/.venv" ] && [ -f "$SCRIPT_DIR/.venv/bin/activate" ]; then
    # Optional activation for users running the script directly.
    # The script still uses PYTHON_BIN explicitly for execution.
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.venv/bin/activate" >/dev/null 2>&1 || true
fi

AUTH_ENV=()
PROFILES=()
ACTIVE_MODULES=()
SCANNERS=("nuclei" "wpscan")

pause_screen() {
    echo ""
    echo -ne "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

show_banner() {
    clear
    echo -e "${CYAN}"
    cat <<'BANNER'
  ============================================================
             ReconnV2 Interactive - HONEST EDITION
  ============================================================
BANNER
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}[*] $*${NC}"
}

print_ok() {
    echo -e "${GREEN}[+] $*${NC}"
}

print_warn() {
    echo -e "${YELLOW}[!] $*${NC}"
}

print_err() {
    echo -e "${RED}[!] $*${NC}"
}

ask_yes_no() {
    local prompt="$1"
    local default="${2:-N}"
    local answer=""
    local hint="[y/N]"

    if [[ "$default" =~ ^[Yy]$ ]]; then
        hint="[Y/n]"
    fi

    echo -ne "${CYAN}${prompt} ${hint}: ${NC}"
    read -r answer
    if [ -z "$answer" ]; then
        answer="$default"
    fi
    [[ "$answer" =~ ^[Yy]$ ]]
}

run_command() {
    local -a cmd=("$@")
    echo ""
    echo -e "${CYAN}> ${cmd[*]}${NC}"
    echo ""
    "${cmd[@]}"
    return $?
}

run_recon() {
    run_command "$PYTHON_BIN" -m recon_cli "$@"
}

ensure_cli_runtime() {
    if "$PYTHON_BIN" -m recon_cli --help >/dev/null 2>&1; then
        return 0
    fi
    print_err "recon_cli is not ready for $PYTHON_BIN."
    print_info "Run ./install.sh to create the virtual environment and install dependencies."
    exit 1
}

run_scan_command() {
    local -a cmd=("$@")
    echo ""
    echo -e "${CYAN}> ${cmd[*]}${NC}"
    echo ""
    if [ "${#AUTH_ENV[@]}" -gt 0 ]; then
        env "${AUTH_ENV[@]}" "${cmd[@]}"
    else
        "${cmd[@]}"
    fi
    return $?
}

load_profiles() {
    local output=""
    if ! output="$($PYTHON_BIN - <<'PY'
from recon_cli import config
base = ["passive", "full", "fuzz-only"]
profiles = sorted(set(base) | set(config.available_profiles().keys()))
print("\n".join(profiles))
PY
)"; then
        print_warn "Could not read profiles dynamically. Falling back to defaults."
        PROFILES=("passive" "full" "fuzz-only")
        return
    fi

    mapfile -t PROFILES <<<"$output"
    if [ "${#PROFILES[@]}" -eq 0 ]; then
        PROFILES=("passive" "full" "fuzz-only")
    fi
}

load_active_modules() {
    local output=""
    if ! output="$($PYTHON_BIN - <<'PY'
from recon_cli.active import modules
mods = modules.available_modules() or []
print("\n".join(mods))
PY
)"; then
        ACTIVE_MODULES=("backup" "cors" "diff" "js-secrets")
        return
    fi

    mapfile -t ACTIVE_MODULES <<<"$output"
}

profile_exists() {
    local wanted="$1"
    local item
    for item in "${PROFILES[@]}"; do
        if [ "$item" = "$wanted" ]; then
            return 0
        fi
    done
    return 1
}

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

is_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
    local o
    for o in "$o1" "$o2" "$o3" "$o4"; do
        if [ "$o" -gt 255 ] 2>/dev/null || [ "$o" -lt 0 ] 2>/dev/null; then
            return 1
        fi
    done
    return 0
}

file_has_ip() {
    local file="$1"
    local line=""
    local host=""
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line%%[[:space:]]*}"
        [ -z "$line" ] && continue
        host="$(extract_host "$line")"
        if is_ipv4 "$host"; then
            return 0
        fi
    done <"$file"
    return 1
}

prompt_targets() {
    TARGET=""
    TARGETS_FILE=""

    echo ""
    echo -ne "${CYAN}Target (domain/IP/URL) or targets file path: ${NC}"
    read -r input

    if [ -z "$input" ]; then
        print_err "Target is required"
        return 1
    fi

    if [ -f "$input" ]; then
        TARGETS_FILE="$input"
        print_ok "Using targets file: $TARGETS_FILE"
    else
        TARGET="$input"
        print_ok "Using target: $TARGET"
    fi
    return 0
}

reset_auth_env() {
    AUTH_ENV=()
}

prompt_auth() {
    reset_auth_env

    if ! ask_yes_no "Enable authenticated scan for this run?" "N"; then
        return
    fi

    AUTH_ENV+=("RECON_ENABLE_AUTH_SCAN=1")

    echo ""
    echo -e "${WHITE}Auth mode:${NC}"
    echo -e "${WHITE}[1]${NC} Bearer token"
    echo -e "${WHITE}[2]${NC} Headers (k:v; k2:v2)"
    echo -e "${WHITE}[3]${NC} Cookies (k=v; k2=v2)"
    echo -e "${WHITE}[4]${NC} Login flow (URL + payload)"
    echo -e "${WHITE}[5]${NC} Basic auth (user/pass)"
    echo -e "${WHITE}[6]${NC} Auth profile name"
    echo -ne "${MAGENTA}Choice: ${NC}"

    local mode=""
    read -r mode

    case "$mode" in
        1)
            local token=""
            echo -ne "${CYAN}Bearer token: ${NC}"
            read -r token
            [ -n "$token" ] && AUTH_ENV+=("RECON_AUTH_BEARER=$token")
            ;;
        2)
            local headers=""
            echo -ne "${CYAN}Headers: ${NC}"
            read -r headers
            [ -n "$headers" ] && AUTH_ENV+=("RECON_AUTH_HEADERS=$headers")
            ;;
        3)
            local cookies=""
            echo -ne "${CYAN}Cookies: ${NC}"
            read -r cookies
            [ -n "$cookies" ] && AUTH_ENV+=("RECON_AUTH_COOKIES=$cookies")
            ;;
        4)
            local login_url=""
            local login_method=""
            local login_payload=""
            local login_headers=""
            local content_type=""
            local success_re=""
            local fail_re=""
            local cookie_names=""

            echo -ne "${CYAN}Login URL: ${NC}"
            read -r login_url
            [ -n "$login_url" ] && AUTH_ENV+=("RECON_AUTH_LOGIN_URL=$login_url")

            echo -ne "${CYAN}HTTP method [POST]: ${NC}"
            read -r login_method
            login_method="${login_method:-POST}"
            AUTH_ENV+=("RECON_AUTH_LOGIN_METHOD=$login_method")

            echo -ne "${CYAN}Payload: ${NC}"
            read -r login_payload
            [ -n "$login_payload" ] && AUTH_ENV+=("RECON_AUTH_LOGIN_PAYLOAD=$login_payload")

            echo -ne "${CYAN}Content-Type [application/x-www-form-urlencoded]: ${NC}"
            read -r content_type
            content_type="${content_type:-application/x-www-form-urlencoded}"
            AUTH_ENV+=("RECON_AUTH_LOGIN_CONTENT_TYPE=$content_type")

            echo -ne "${CYAN}Login headers (optional): ${NC}"
            read -r login_headers
            [ -n "$login_headers" ] && AUTH_ENV+=("RECON_AUTH_LOGIN_HEADERS=$login_headers")

            echo -ne "${CYAN}Success regex (optional): ${NC}"
            read -r success_re
            [ -n "$success_re" ] && AUTH_ENV+=("RECON_AUTH_LOGIN_SUCCESS_REGEX=$success_re")

            echo -ne "${CYAN}Fail regex (optional): ${NC}"
            read -r fail_re
            [ -n "$fail_re" ] && AUTH_ENV+=("RECON_AUTH_LOGIN_FAIL_REGEX=$fail_re")

            echo -ne "${CYAN}Cookie names (optional, comma-separated): ${NC}"
            read -r cookie_names
            [ -n "$cookie_names" ] && AUTH_ENV+=("RECON_AUTH_LOGIN_COOKIE_NAMES=$cookie_names")
            ;;
        5)
            local user=""
            local pass=""
            echo -ne "${CYAN}Basic auth username: ${NC}"
            read -r user
            echo -ne "${CYAN}Basic auth password: ${NC}"
            read -rs pass
            echo ""
            [ -n "$user" ] && AUTH_ENV+=("RECON_AUTH_BASIC_USER=$user")
            [ -n "$pass" ] && AUTH_ENV+=("RECON_AUTH_BASIC_PASS=$pass")
            ;;
        6)
            local profile_name=""
            echo -ne "${CYAN}Auth profile name: ${NC}"
            read -r profile_name
            [ -n "$profile_name" ] && AUTH_ENV+=("RECON_AUTH_PROFILE=$profile_name")
            ;;
        *)
            print_warn "Invalid auth mode. Running without auth."
            reset_auth_env
            ;;
    esac
}

collect_active_modules() {
    local -n out_ref=$1
    out_ref=()

    if [ "${#ACTIVE_MODULES[@]}" -eq 0 ]; then
        return
    fi

    local module
    for module in "${ACTIVE_MODULES[@]}"; do
        if ask_yes_no "Enable active module '$module'?" "N"; then
            out_ref+=("$module")
        fi
    done
}

collect_scanners() {
    local -n out_ref=$1
    out_ref=()

    local scanner
    for scanner in "${SCANNERS[@]}"; do
        if ask_yes_no "Enable scanner '$scanner'?" "N"; then
            out_ref+=("$scanner")
        fi
    done
}

run_scan_flow() {
    local profile="$1"
    shift
    local -a fixed_args=("$@")

    if ! prompt_targets; then
        pause_screen
        return
    fi

    local inline_flag="0"
    local allow_ip="0"
    local force_flag="0"
    local insecure_flag="0"
    local split_targets="0"
    local project=""
    local incremental_from=""
    local wordlist=""
    local max_screenshots=""
    local -a selected_modules=()
    local -a selected_scanners=()

    if ask_yes_no "Run inline now?" "Y"; then
        inline_flag="1"
    fi

    echo -ne "${CYAN}Project (optional): ${NC}"
    read -r project

    echo -ne "${CYAN}Incremental from job_id (optional): ${NC}"
    read -r incremental_from

    echo -ne "${CYAN}Wordlist path (optional): ${NC}"
    read -r wordlist
    if [ -n "$wordlist" ] && [ ! -f "$wordlist" ]; then
        print_warn "Wordlist file not found; ignoring."
        wordlist=""
    fi

    echo -ne "${CYAN}Max screenshots (optional integer): ${NC}"
    read -r max_screenshots
    if [ -n "$max_screenshots" ] && ! [[ "$max_screenshots" =~ ^[0-9]+$ ]]; then
        print_warn "Invalid number; ignoring max screenshots."
        max_screenshots=""
    fi

    if ask_yes_no "Force re-run all stages?" "N"; then
        force_flag="1"
    fi

    if ask_yes_no "Disable TLS verification (--insecure)?" "N"; then
        insecure_flag="1"
    fi

    if [ -n "$TARGETS_FILE" ]; then
        if file_has_ip "$TARGETS_FILE"; then
            allow_ip="1"
        fi
        if ask_yes_no "Split targets file into one job per target?" "N"; then
            split_targets="1"
        fi
    else
        local host=""
        host="$(extract_host "$TARGET")"
        if is_ipv4 "$host"; then
            allow_ip="1"
        fi
    fi

    collect_active_modules selected_modules
    collect_scanners selected_scanners

    prompt_auth

    # Inject performance/hardening variables
    [ -n "${RECON_STAGE_TIMEOUT:-}" ] && AUTH_ENV+=("RECON_STAGE_TIMEOUT=$RECON_STAGE_TIMEOUT")
    [ -n "${RECON_CB_THRESHOLD:-}" ] && AUTH_ENV+=("RECON_HOST_CIRCUIT_BREAKER_THRESHOLD=$RECON_CB_THRESHOLD")
    [ -n "${RECON_PARALLEL_STAGES:-}" ] && AUTH_ENV+=("RECON_PARALLEL_STAGES=$RECON_PARALLEL_STAGES")

    local -a cmd=("$PYTHON_BIN" -m recon_cli scan)

    if [ -n "$TARGETS_FILE" ]; then
        cmd+=(--targets-file "$TARGETS_FILE")
    else
        cmd+=("$TARGET")
    fi

    cmd+=(--profile "$profile")

    if [ "$inline_flag" = "1" ]; then
        cmd+=(--inline)
    fi
    if [ "$allow_ip" = "1" ]; then
        cmd+=(--allow-ip)
    fi
    if [ "$force_flag" = "1" ]; then
        cmd+=(--force)
    fi
    if [ "$insecure_flag" = "1" ]; then
        cmd+=(--insecure)
    fi
    if [ "$split_targets" = "1" ]; then
        cmd+=(--split-targets)
    fi
    if [ -n "$project" ]; then
        cmd+=(--project "$project")
    fi
    if [ -n "$incremental_from" ]; then
        cmd+=(--incremental-from "$incremental_from")
    fi
    if [ -n "$wordlist" ]; then
        cmd+=(--wordlist "$wordlist")
    fi
    if [ -n "$max_screenshots" ]; then
        cmd+=(--max-screenshots "$max_screenshots")
    fi

    local module
    for module in "${selected_modules[@]}"; do
        cmd+=(--active-module "$module")
    done

    local scanner
    for scanner in "${selected_scanners[@]}"; do
        cmd+=(--scanner "$scanner")
    done

    cmd+=("${fixed_args[@]}")

    print_info "Starting scan with profile: $profile"
    if run_scan_command "${cmd[@]}"; then
        print_ok "Scan command finished"
    else
        print_err "Scan command failed"
    fi

    reset_auth_env
    pause_screen
}

select_profile_and_scan() {
    echo ""
    echo -e "${WHITE}Available profiles:${NC}"

    local i=1
    local profile
    for profile in "${PROFILES[@]}"; do
        echo -e "${WHITE}[$i]${NC} $profile"
        i=$((i + 1))
    done

    echo -e "${WHITE}[0]${NC} Cancel"
    echo -ne "${MAGENTA}Choice: ${NC}"

    local choice=""
    read -r choice

    if [ "$choice" = "0" ]; then
        return
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        print_err "Invalid choice"
        pause_screen
        return
    fi

    local idx=$((choice - 1))
    if [ "$idx" -lt 0 ] || [ "$idx" -ge "${#PROFILES[@]}" ]; then
        print_err "Invalid choice"
        pause_screen
        return
    fi

    local selected="${PROFILES[$idx]}"
    run_scan_flow "$selected"
}

scan_quick() {
    if profile_exists "quick"; then
        run_scan_flow "quick"
    else
        print_warn "Profile 'quick' not available; using 'passive'."
        run_scan_flow "passive"
    fi
}

scan_passive() {
    run_scan_flow "passive"
}

scan_full() {
    run_scan_flow "full"
}

scan_deep() {
    if profile_exists "deep"; then
        run_scan_flow "deep"
    else
        print_warn "Profile 'deep' not available; using 'full'."
        run_scan_flow "full"
    fi
}

scan_api_only() {
    if profile_exists "api-only"; then
        run_scan_flow "api-only"
    else
        print_warn "Profile 'api-only' not available; using 'full'."
        run_scan_flow "full"
    fi
}

scan_secure() {
    if profile_exists "secure"; then
        run_scan_flow "secure"
    else
        print_warn "Profile 'secure' not available; using 'passive'."
        run_scan_flow "passive"
    fi
}

scan_fuzz_only() {
    run_scan_flow "fuzz-only"
}

scan_wordpress() {
    print_info "WordPress mode = full profile + wpscan scanner"
    run_scan_flow "full" --scanner wpscan
}

list_jobs() {
    echo ""
    echo -ne "${CYAN}Status filter (queued/running/finished/failed, optional): ${NC}"
    local status_filter=""
    read -r status_filter

    echo -ne "${CYAN}Project filter (optional): ${NC}"
    local project_filter=""
    read -r project_filter

    if [ -n "$status_filter" ] && [ -n "$project_filter" ]; then
        run_recon list-jobs "$status_filter" --project "$project_filter"
    elif [ -n "$status_filter" ]; then
        run_recon list-jobs "$status_filter"
    elif [ -n "$project_filter" ]; then
        run_recon list-jobs --project "$project_filter"
    else
        run_recon list-jobs
    fi
    pause_screen
}

job_status() {
    echo ""
    echo -ne "${CYAN}Job ID: ${NC}"
    local job_id=""
    read -r job_id
    if [ -z "$job_id" ]; then
        print_err "Job ID is required"
        pause_screen
        return
    fi
    run_recon status "$job_id"
    pause_screen
}

tail_logs() {
    echo ""
    echo -ne "${CYAN}Job ID: ${NC}"
    local job_id=""
    read -r job_id
    if [ -z "$job_id" ]; then
        print_err "Job ID is required"
        pause_screen
        return
    fi
    run_recon tail-logs "$job_id"
    pause_screen
}

rerun_job() {
    echo ""
    echo -ne "${CYAN}Job ID to rerun: ${NC}"
    local job_id=""
    read -r job_id
    if [ -z "$job_id" ]; then
        print_err "Job ID is required"
        pause_screen
        return
    fi

    local mode=""
    echo ""
    echo -e "${WHITE}Rerun mode:${NC}"
    echo -e "${WHITE}[1]${NC} Resume from checkpoints (default)"
    echo -e "${WHITE}[2]${NC} Full restart (--restart)"
    echo -e "${WHITE}[3]${NC} Replay specific stages (--stages)"
    echo -ne "${MAGENTA}Choice [1]: ${NC}"
    read -r mode
    mode="${mode:-1}"

    local -a cmd=("$PYTHON_BIN" -m recon_cli rerun "$job_id")

    case "$mode" in
        2)
            cmd+=(--restart)
            if ask_yes_no "Keep existing results?" "N"; then
                cmd+=(--keep-results)
            fi
            ;;
        3)
            echo -ne "${CYAN}Stage names (comma-separated): ${NC}"
            local stage_list=""
            read -r stage_list
            if [ -z "$stage_list" ]; then
                print_err "Stage list is required for stage replay"
                pause_screen
                return
            fi
            cmd+=(--stages "$stage_list")
            ;;
        1|*)
            ;;
    esac

    run_scan_command "${cmd[@]}"
    pause_screen
}

requeue_job() {
    echo ""
    echo -ne "${CYAN}Job ID to requeue: ${NC}"
    local job_id=""
    read -r job_id
    if [ -z "$job_id" ]; then
        print_err "Job ID is required"
        pause_screen
        return
    fi
    run_recon requeue "$job_id"
    pause_screen
}

cancel_job() {
    echo ""
    echo -ne "${CYAN}Job ID to cancel: ${NC}"
    local job_id=""
    read -r job_id
    if [ -z "$job_id" ]; then
        print_err "Job ID is required"
        pause_screen
        return
    fi

    local wait_seconds="30"
    echo -ne "${CYAN}Wait seconds before timeout [30]: ${NC}"
    read -r wait_seconds
    wait_seconds="${wait_seconds:-30}"
    if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then
        wait_seconds="30"
    fi

    local -a cmd=("$PYTHON_BIN" -m recon_cli cancel "$job_id" --wait "$wait_seconds")

    if ask_yes_no "Requeue after cancel?" "Y"; then
        cmd+=(--requeue)
    else
        cmd+=(--no-requeue)
    fi

    if ask_yes_no "Use hard kill if graceful stop fails?" "N"; then
        cmd+=(--hard)
    fi

    run_scan_command "${cmd[@]}"
    pause_screen
}

verify_job() {
    echo ""
    echo -ne "${CYAN}Job ID to verify: ${NC}"
    local job_id=""
    read -r job_id
    if [ -z "$job_id" ]; then
        print_err "Job ID is required"
        pause_screen
        return
    fi
    run_recon verify-job "$job_id"
    pause_screen
}

export_results() {
    echo ""
    echo -ne "${CYAN}Job ID: ${NC}"
    local job_id=""
    read -r job_id
    if [ -z "$job_id" ]; then
        print_err "Job ID is required"
        pause_screen
        return
    fi

    echo -ne "${CYAN}Format [jsonl|triage|txt|zip] [jsonl]: ${NC}"
    local format=""
    read -r format
    format="${format:-jsonl}"

    local -a cmd=("$PYTHON_BIN" -m recon_cli export "$job_id" --format "$format")

    if [ "$format" = "jsonl" ] || [ "$format" = "triage" ]; then
        if ask_yes_no "Verified only?" "N"; then
            cmd+=(--verified-only)
        fi
        if ask_yes_no "Proof required?" "N"; then
            cmd+=(--proof-required)
        fi
        if ask_yes_no "Hunter mode export?" "N"; then
            cmd+=(--hunter-mode)
        fi
        echo -ne "${CYAN}Limit findings (optional): ${NC}"
        local limit=""
        read -r limit
        if [ -n "$limit" ] && [[ "$limit" =~ ^[0-9]+$ ]] && [ "$limit" -gt 0 ]; then
            cmd+=(--limit "$limit")
        fi
    fi

    run_scan_command "${cmd[@]}"
    pause_screen
}

generate_report() {
    echo ""
    echo -ne "${CYAN}Job ID: ${NC}"
    local job_id=""
    read -r job_id

    echo -ne "${CYAN}Format [html|json|csv|markdown|xml|pdf] [html]: ${NC}"
    local format=""
    read -r format
    format="${format:-html}"

    local -a cmd=("$PYTHON_BIN" -m recon_cli report)
    if [ -n "$job_id" ]; then
        cmd+=("$job_id")
    fi
    cmd+=(--format "$format")

    echo -ne "${CYAN}Output file path (optional): ${NC}"
    local output=""
    read -r output
    if [ -n "$output" ]; then
        cmd+=(--output "$output")
    fi

    echo -ne "${CYAN}Custom title (optional): ${NC}"
    local title=""
    read -r title
    if [ -n "$title" ]; then
        cmd+=(--title "$title")
    fi

    if ask_yes_no "Executive summary only?" "N"; then
        cmd+=(--executive)
    fi
    if ask_yes_no "Verified only?" "N"; then
        cmd+=(--verified-only)
    fi
    if ask_yes_no "Proof required?" "N"; then
        cmd+=(--proof-required)
    fi
    if [ "$format" = "html" ] && ask_yes_no "Hunter mode preset?" "N"; then
        cmd+=(--hunter-mode)
    fi

    run_scan_command "${cmd[@]}"
    pause_screen
}

set_stage_timeout() {
    echo ""
    echo -ne "${CYAN}Stage timeout in seconds [3600]: ${NC}"
    local timeout=""
    read -r timeout
    timeout="${timeout:-3600}"
    if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
        print_err "Invalid number"
        return
    fi
    export RECON_STAGE_TIMEOUT="$timeout"
    print_ok "Stage timeout set to ${timeout}s"
    pause_screen
}

set_cb_threshold() {
    echo ""
    echo -ne "${CYAN}Host Circuit Breaker Threshold [10]: ${NC}"
    local threshold=""
    read -r threshold
    threshold="${threshold:-10}"
    if ! [[ "$threshold" =~ ^[0-9]+$ ]]; then
        print_err "Invalid number"
        return
    fi
    export RECON_CB_THRESHOLD="$threshold"
    print_ok "Circuit breaker threshold set to ${threshold}"
    pause_screen
}

toggle_parallel() {
    if [ "${RECON_PARALLEL:-ON}" = "ON" ]; then
        export RECON_PARALLEL="OFF"
        export RECON_PARALLEL_STAGES="0"
    else
        export RECON_PARALLEL="ON"
        export RECON_PARALLEL_STAGES="1"
    fi
    print_ok "Parallel stages: $RECON_PARALLEL"
    pause_screen
}

run_pdf_report() {
    echo ""
    echo -ne "${CYAN}Job ID: ${NC}"
    local job_id=""
    read -r job_id
    if [ -z "$job_id" ]; then
        print_err "Job ID is required"
        pause_screen
        return
    fi
    run_recon pdf "$job_id"
    pause_screen
}

run_doctor() {
    local -a cmd=("$PYTHON_BIN" -m recon_cli doctor)
    if ask_yes_no "Run with --fix?" "N"; then
        cmd+=(--fix)
    fi
    if ask_yes_no "Run with --fix-deps?" "N"; then
        cmd+=(--fix-deps)
    fi
    run_scan_command "${cmd[@]}"
    pause_screen
}

prune_jobs() {
    echo ""
    echo -ne "${CYAN}Prune finished jobs older than N days [7]: ${NC}"
    local days=""
    read -r days
    days="${days:-7}"
    if ! [[ "$days" =~ ^[0-9]+$ ]] || [ "$days" -lt 1 ]; then
        print_warn "Invalid days value; using 7"
        days="7"
    fi

    local -a cmd=("$PYTHON_BIN" -m recon_cli prune --days "$days")
    if ask_yes_no "Archive instead of delete?" "N"; then
        cmd+=(--archive)
    fi

    run_scan_command "${cmd[@]}"
    pause_screen
}

run_wizard() {
    run_recon wizard
    pause_screen
}

run_interactive() {
    run_recon interactive
    pause_screen
}

run_quickstart() {
    run_recon quickstart
    pause_screen
}

start_web_dashboard() {
    print_info "Starting web dashboard (Ctrl+C to stop)."
    run_recon serve
    pause_screen
}

setup_completions() {
    echo ""
    echo -ne "${CYAN}Shell [bash|zsh|fish|powershell] [bash]: ${NC}"
    local shell_name=""
    read -r shell_name
    shell_name="${shell_name:-bash}"

    local -a cmd=("$PYTHON_BIN" -m recon_cli completions --shell "$shell_name")

    if ask_yes_no "Install completions?" "N"; then
        cmd+=(--install)
    elif ask_yes_no "Show completion script only?" "Y"; then
        cmd+=(--show)
    fi

    run_scan_command "${cmd[@]}"
    pause_screen
}

show_schema() {
    run_recon schema --format json
    pause_screen
}

show_trace() {
    echo ""
    echo -ne "${CYAN}Job ID (optional, leave blank for last trace): ${NC}"
    local job_id=""
    read -r job_id

    echo -ne "${CYAN}Show last N events [8]: ${NC}"
    local events=""
    read -r events
    events="${events:-8}"
    if ! [[ "$events" =~ ^[0-9]+$ ]]; then
        events="8"
    fi

    local -a cmd=("$PYTHON_BIN" -m recon_cli trace)
    if [ -n "$job_id" ]; then
        cmd+=("$job_id")
    fi
    cmd+=(--events "$events")

    if ask_yes_no "Output JSON?" "N"; then
        cmd+=(--json)
    fi

    run_scan_command "${cmd[@]}"
    pause_screen
}

cache_stats() {
    run_recon cache-stats
    pause_screen
}

cache_clear() {
    if ask_yes_no "Clear all cached data?" "N"; then
        run_recon cache-clear
    else
        print_warn "Cache clear cancelled"
    fi
    pause_screen
}

show_main_menu() {
    echo -e "${WHITE}==================== Scan Profiles ====================${NC}"
    echo -e "${WHITE}[1]${NC} Quick scan"
    echo -e "${WHITE}[2]${NC} Passive scan"
    echo -e "${WHITE}[3]${NC} Full scan"
    echo -e "${WHITE}[4]${NC} Deep scan"
    echo -e "${WHITE}[5]${NC} Ultra-deep scan"
    echo -e "${WHITE}[6]${NC} API-only scan"
    echo -e "${WHITE}[7]${NC} Secure scan"
    echo -e "${WHITE}[8]${NC} Fuzz-only scan"
    echo -e "${WHITE}[9]${NC} WordPress mode (full + wpscan)"
    echo -e "${WHITE}[10]${NC} Select profile manually"
    echo -e "${WHITE}==================== Job Control ======================${NC}"
    echo -e "${WHITE}[11]${NC} List jobs"
    echo -e "${WHITE}[12]${NC} Job status"
    echo -e "${WHITE}[13]${NC} Tail job logs"
    echo -e "${WHITE}[14]${NC} Rerun job"
    echo -e "${WHITE}[15]${NC} Requeue job"
    echo -e "${WHITE}[16]${NC} Cancel running job"
    echo -e "${WHITE}[17]${NC} Verify job files"
    echo -e "${WHITE}==================== Hardening & Perf =================${NC}"
    echo -e "${WHITE}[18]${NC} Set Stage Timeout (Current: ${RECON_STAGE_TIMEOUT:-3600}s)"
    echo -e "${WHITE}[19]${NC} Host Circuit Breaker (Threshold: ${RECON_CB_THRESHOLD:-10})"
    echo -e "${WHITE}[20]${NC} Toggle Parallel Stages (${RECON_PARALLEL:-ON})"
    echo -e "${WHITE}==================== Output / Reports =================${NC}"
    echo -e "${WHITE}[21]${NC} Export results"
    echo -e "${WHITE}[22]${NC} Generate report"
    echo -e "${WHITE}[23]${NC} Generate PDF report"
    echo -e "${WHITE}==================== Utilities ========================${NC}"
    echo -e "${WHITE}[24]${NC} Doctor"
    echo -e "${WHITE}[25]${NC} Prune finished jobs"
    echo -e "${WHITE}[26]${NC} Wizard"
    echo -e "${WHITE}[27]${NC} Interactive mode"
    echo -e "${WHITE}[28]${NC} Quickstart guide"
    echo -e "${WHITE}[29]${NC} Web dashboard"
    echo -e "${WHITE}[30]${NC} Shell completions"
    echo -e "${WHITE}[31]${NC} Trace summary"
    echo -e "${WHITE}[32]${NC} Show schema (JSON)"
    echo -e "${WHITE}[33]${NC} Cache stats"
    echo -e "${WHITE}[34]${NC} Cache clear"
    echo -e "${WHITE}[0]${NC} Exit"
    echo ""
    echo -ne "${MAGENTA}Choose: ${NC}"
}

main() {
    ensure_cli_runtime
    load_profiles
    load_active_modules

    while true; do
        show_banner
        echo -e "${BLUE}Python: ${PYTHON_BIN}${NC}"
        echo -e "${BLUE}Profiles: ${PROFILES[*]}${NC}"
        show_main_menu

        local choice=""
        read -r choice

        case "$choice" in
            1) scan_quick ;;
            2) scan_passive ;;
            3) scan_full ;;
            4) scan_deep ;;
            5) run_scan_flow "ultra-deep" ;;
            6) scan_api_only ;;
            7) scan_secure ;;
            8) scan_fuzz_only ;;
            9) scan_wordpress ;;
            10) select_profile_and_scan ;;
            11) list_jobs ;;
            12) job_status ;;
            13) tail_logs ;;
            14) rerun_job ;;
            15) requeue_job ;;
            16) cancel_job ;;
            17) verify_job ;;
            18) set_stage_timeout ;;
            19) set_cb_threshold ;;
            20) toggle_parallel ;;
            21) export_results ;;
            22) generate_report ;;
            23) run_pdf_report ;;
            24) run_doctor ;;
            25) prune_jobs ;;
            26) run_wizard ;;
            27) run_interactive ;;
            28) run_quickstart ;;
            29) start_web_dashboard ;;
            30) setup_completions ;;
            31) show_trace ;;
            32) show_schema ;;
            33) cache_stats ;;
            34) cache_clear ;;
            0|q|Q)
                echo ""
                print_ok "Bye"
                echo ""
                exit 0
                ;;
            *)
                print_err "Invalid choice"
                sleep 1
                ;;
        esac
    done
}

main

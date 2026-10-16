#!/usr/bin/env bash
#
# php-functions.sh - analyze a phpinfo() "disable_functions" output and
# report which interesting functions are still enabled.
#
# Usage:
#   ./php-functions.sh "system,exec,shell_exec"
#   ./php-functions.sh disabled.txt
#   disabled.txt | ./php-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./php-functions.sh "<disable_functions list>"
  ./php-functions.sh <file-containing-the-list>
  <list-or-file> | ./php-functions.sh
EOF
    exit 1
}

# --- read input (arg > file > stdin) --------------------------------------
if [ $# -eq 1 ]; then
    if [ -f "$1" ]; then
        input=$(<"$1")
    else
        input="$1"
    fi
elif [ $# -gt 1 ]; then
    usage
elif [ ! -t 0 ]; then
    input=$(cat)
else
    usage
fi

# --- normalize: separators -> whitespace -> lines -> lowercase -------------
mapfile -t disabled < <(printf '%s\n' "$input" \
    | tr ',;' ' ' \
    | tr '[:space:]' ' ' \
    | tr -s ' ' ' ' \
    | tr ' ' '\n' \
    | tr '[:upper:]' '[:lower:]' \
    | sed '/^ *$/d')

declare -A disabled_set=()
for fn in "${disabled[@]}"; do
    disabled_set["$fn"]=1
done

# --- helpers ---------------------------------------------------------------
is_enabled() {
    local f="$1" b
    [[ -n "${disabled_set[$f]+x}" ]] && return 1
    for b in "${!disabled_set[@]}"; do
        case "$f" in
            "$b".*|"$b"/*|"$b"::*) return 1 ;;
        esac
    done
    return 0
}

render() {
    local title="$1"; shift
    local fn
    printf "\n${BOLD_RED}# %s #${RESET}\n" "$title"
    for fn in "$@"; do
        if is_enabled "$fn"; then
            printf "   ${BOLD_WHITE}* %s - enabled${RESET}\n" "$fn"
        fi
    done
}

cols=$(tput cols 2>/dev/null || printf '80')
sep=$(printf '%*s' "$cols" '' | tr ' ' '-')

# --- output ----------------------------------------------------------------
printf "\n${GRAY}%s${RESET}\n" "$sep"
printf "${GRAY}%s${RESET}\n" "$input"
printf "${GRAY}%s${RESET}\n" "$sep"

render "Command Execution Functions" \
    system exec passthru pcntl_exec popen pclose \
    proc_open proc_close proc_get_status proc_terminate shell_exec

render "PHP Code Execution Functions" \
    assert preg_replace create_function \
    call_user_func call_user_func_array \
    array_map array_walk usort uasort array_filter

render "Information Disclosure Functions" \
    phpinfo php_uname phpversion getenv putenv \
    ini_get ini_get_all get_cfg_var get_defined_vars \
    get_defined_functions get_include_path get_included_files \
    get_current_user getcwd getlastmod \
    getmyuid getmygid getmyinode getmypid getmymode \
    disk_free_space disk_total_space diskfreespace \
    posix_mkfifo posix_getlogin posix_ttyname posix_getpwuid posix_getgrgid \
    posix_getpid posix_getppid posix_getgroups \
    memory_get_usage sys_get_temp_dir getallheaders \
    apache_get_version apache_get_modules apache_getenv

render "Filesystem Functions" \
    fopen fread fwrite file_get_contents file_put_contents readfile \
    highlight_file show_source file glob scandir opendir readdir \
    chdir chmod chown mkdir rmdir unlink rename copy touch \
    move_uploaded_file parse_ini_file parse_ini_string

render "Network / Misc Functions" \
    fsockopen pfsockopen stream_socket_client stream_socket_server \
    curl_exec curl_multi_exec socket_create socket_connect \
    socket_send socket_recv mail error_log

printf "\n${GRAY}Note: include/include_once/require/require_once/eval are language${RESET}\n"
printf "${GRAY}constructs and cannot be disabled via disable_functions.${RESET}\n\n"

exit 0

#!/usr/bin/env bash
#
# bash-functions.sh — given a list of Bash builtins/commands blocked by a
# restricted shell (rbash, sandbox) or hardening checklist, report which
# dangerous capabilities are still available.
#
# Usage:
#   ./bash-functions.sh "eval,curl,wget"
#   ./bash-functions.sh blocked.txt
#   blocked.txt | ./bash-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./bash-functions.sh "<blocked commands>"
  ./bash-functions.sh <file-containing-the-list>
  <list-or-file> | ./bash-functions.sh
EOF
    exit 1
}

if [ $# -eq 1 ]; then
    if [ -f "$1" ]; then input=$(<"$1"); else input="$1"; fi
elif [ $# -gt 1 ]; then
    usage
elif [ ! -t 0 ]; then
    input=$(cat)
else
    usage
fi

mapfile -t blocked < <(printf '%s\n' "$input" \
    | tr ',;' ' ' | tr -s '[:space:]' ' ' | tr ' ' '\n' | sed '/^ *$/d')

declare -A blocked_set=()
for f in "${blocked[@]}"; do blocked_set["$f"]=1; done

is_available() {
    local f="$1" b
    [[ -n "${blocked_set[$f]+x}" ]] && return 1
    for b in "${!blocked_set[@]}"; do
        case "$f" in
            "$b".*|"$b"/*|"$b"::*) return 1 ;;
        esac
    done
    return 0
}

render() {
    local title="$1"; shift
    local f
    printf "\n${BOLD_RED}# %s #${RESET}\n" "$title"
    for f in "$@"; do
        if is_available "$f"; then
            printf "   ${BOLD_WHITE}* %s - available${RESET}\n" "$f"
        fi
    done
}

cols=$(tput cols 2>/dev/null || printf '80')
sep=$(printf '%*s' "$cols" '' | tr ' ' '-')

printf "\n${GRAY}%s${RESET}\n" "$sep"
printf "${GRAY}%s${RESET}\n" "$input"
printf "${GRAY}%s${RESET}\n" "$sep"

render "Code Execution" \
    eval exec source . command builtin \
    export set unset trap

render "Command Execution / Substitution" \
    "\` (backticks)" "\$() (command substitution)" "\$(( )) (arithmetic)" \
    "\$(<file)" "<(process substitution)" ">(process substitution)"

render "Shell Features / Bypasses" \
    "\ (escaped command)" "(subshell)" "; (command separator)" \
    "&&" "||" "| (pipe)" "& (background)"

render "Network Tools" \
    curl wget nc netcat socat telnet ssh \
    openssl s_client nslookup dig host \
    ping traceroute mtr

render "Filesystem" \
    cat head tail more less \
    grep sed awk cut sort uniq \
    find ls cp mv rm mkdir rmdir \
    chmod chown touch readlink realpath

render "System Info / Enumeration" \
    whoami id hostname uname pwd \
    env printenv set -o history ps \
    top df du free lsof ss netstat \
    crontab systemctl service docker

render "Persistence / Privilege" \
    sudo su useradd usermod groupadd \
    passwd chsh newgrp setuid \
    nohup at batch

render "Encoding / Exfiltration" \
    base64 xxd od hexdump \
    openssl enc gzip tar zip \
    python3 perl ruby

printf "\n${GRAY}Note: rbash is trivially bypassed; real isolation needs${RESET}\n"
printf "${GRAY}seccomp/containers. Check the "bash_functions.sh" builtins too.${RESET}\n\n"

exit 0

#!/usr/bin/env bash
#
# perl-functions.sh — given a list of Perl functions blocked by a taint
# mode / hardening checklist, report which dangerous capabilities are still
# available.
#
# Usage:
#   ./perl-functions.sh "system,open,unpack"
#   ./perl-functions.sh blocked.txt
#   blocked.txt | ./perl-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./perl-functions.sh "<blocked functions>"
  ./perl-functions.sh <file-containing-the-list>
  <list-or-file> | ./perl-functions.sh
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

render "Command Execution" \
    system exec fork open -e \
    "qx`` (backticks)" system

render "Code Execution" \
    eval do require use \
    "s///e (regex eval)" \
    String::Eval Safe

render "Deserialization" \
    Storable::thaw Storable::retrieve \
    Data::Dumper::Deparse \
    JSON::PP::decode_json

render "Filesystem" \
    open close read write \
    unlink rename chmod chown \
    mkdir rmdir opendir readdir \
    glob stat lstat -f

render "Network / SSRF" \
    IO::Socket::INET IO::Socket::UNIX \
    LWP::Simple::get "HTTP::Tiny->get" \
    Socket::sockaddr_in Net::FTP Net::SMTP \
    "IO::Socket::SSL->new"

render "System / Env Disclosure" \
    %ENV $0 $^O "(osname)" $] "(perl version)" \
    getpwuid getgrgid getlogin \
    gethostname localtime gmtime

render "Native / FFI" \
    Inline::C XS pack unpack \
    DynaLoader dl_load_file

printf "\n${GRAY}Note: taint mode (perl -T) is the main mitigation, but it does${RESET}\n"
printf "${GRAY}not block these functions; it only refuses tainted arguments.${RESET}\n\n"

exit 0

#!/usr/bin/env bash
#
# go-functions.sh — given a list of Go stdlib packages/functions blocked by
# a policy or hardening checklist, report which dangerous primitives are
# still available.
#
# Usage:
#   ./go-functions.sh "os/exec,net/http"
#   ./go-functions.sh blocked.txt
#   blocked.txt | ./go-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./go-functions.sh "<blocked packages>"
  ./go-functions.sh <file-containing-the-list>
  <list-or-file> | ./go-functions.sh
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
    os/exec.Command os/exec.CommandContext os.StartProcess \
    syscall.Exec syscall.ForkExec syscall.StartProcess

render "Reflection / Runtime" \
    reflect.ValueOf reflect.TypeOf reflect.New \
    unsafe.Pointer unsafe.Offsetof unsafe.Sizeof \
    runtime.Callers runtime.FuncForPC

render "Deserialization / Marshal" \
    encoding/json.Unmarshal encoding/json.Decoder \
    encoding/gob.Decoder encoding/xml.Unmarshal \
    encoding/binary.Read yaml.Unmarshal

render "Filesystem" \
    os.Open os.Create os.ReadFile os.WriteFile \
    os.Remove os.RemoveAll os.Rename os.Chmod os.Chown \
    os.ReadDir os.MkdirAll os.Stat filepath.Walk \
    io/ioutil.ReadFile io/ioutil.WriteFile os.UserHomeDir

render "Network / SSRF" \
    net/http.Get net/http.Post net/http.NewRequest \
    net.Dial net.DialTCP net.Listen net.ListenTCP \
    net.DialUDP net.DialUnix net/http.Client.Do \
    net/smtp.SendMail

render "System / Env Disclosure" \
    os.Getenv os.LookupEnv os.Getwd os.Getuid os.Getgid \
    os.Hostname os.UserHomeDir os.Getpid runtime.GOOS \
    runtime.GOARCH runtime.NumCPU

render "CGo / FFI" \
    cgo import "C" syscall.Syscall syscall.DllProc

render "SQL / Data Access" \
    database/sql.Open database/sql.Query \
    database/sql.QueryRow database/sql.Exec

printf "\n${GRAY}Note: unsafe and cgo bypass the type system and should be${RESET}\n"
printf "${GRAY}treated as code-execution primitives if reachable.${RESET}\n\n"

exit 0

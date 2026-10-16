#!/usr/bin/env bash
#
# powershell-functions.sh — given a list of PowerShell cmdlets/.NET types
# blocked by an execution policy / AppLocker / WDAC or a hardening
# checklist, report which dangerous primitives are still available.
#
# Usage:
#   ./powershell-functions.sh "Invoke-Expression,Get-Content"
#   ./powershell-functions.sh blocked.txt
#   blocked.txt | ./powershell-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./powershell-functions.sh "<blocked cmdlets>"
  ./powershell-functions.sh <file-containing-the-list>
  <list-or-file> | ./powershell-functions.sh
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
    Invoke-Expression Invoke-Command Invoke-Item \
    Start-Process Start-Job Start-ThreadJob \
    "& (call operator)" ". (dot source)" iex

render "Code Execution" \
    Add-Type Add-Assembly New-Object -TypeName \
    Invoke-Command -ScriptBlock

render "Deserialization" \
    ConvertFrom-Json ConvertFrom-Xml \
    [System.Web.Script.Serialization.JavaScriptSerializer]::Deserialize \
    [System.Runtime.Serialization.Formatters.Binary.BinaryFormatter]::Deserialize

render "Filesystem" \
    Get-Content Set-Content Add-Content Out-File \
    Remove-Item Rename-Item Copy-Item Move-Item \
    New-Item Get-ChildItem Get-Item Test-Path

render "Network / SSRF" \
    Invoke-WebRequest Invoke-RestMethod New-WebServiceProxy \
    Test-NetConnection Test-NetworkConnection \
    [System.Net.Sockets.TcpClient] \
    [System.Net.WebClient] Start-BitsTransfer

render "System / Env Disclosure" \
    Get-ChildItem Env: Get-EnvironmentVariable \
    Get-ComputerInfo Get-ComputerName Get-Process \
    Get-CimInstance Win32_OperatingSystem Get-Location

render "Active Directory / Domain" \
    Get-ADUser Get-ADGroup Get-ADComputer \
    Get-ADDomain Get-ADDomainController

render "Credential / Token" \
    Get-Credential ConvertFrom-SecureString \
    ConvertTo-SecureString New-Service

render "Weak Crypto" \
    [System.Security.Cryptography.MD5] \
    [System.Security.Cryptography.SHA1] \
    [System.Security.Cryptography.DES]

printf "\n${GRAY}Note: PowerShell execution policy is not a security boundary;${RESET}\n"
printf "${GRAY}AppLocker/WDAC or Constrained Language Mode are the real controls.${RESET}\n\n"

exit 0

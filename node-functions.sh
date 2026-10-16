#!/usr/bin/env bash
#
# node-functions.sh — given a list of Node.js APIs blocked by a sandbox
# (vm, policy, container hardening) or a hardening checklist, report which
# dangerous primitives are still available.
#
# Usage:
#   ./node-functions.sh "child_process.exec,fs.readFile"
#   ./node-functions.sh blocked.txt
#   blocked.txt | ./node-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./node-functions.sh "<blocked functions>"
  ./node-functions.sh <file-containing-the-list>
  <list-or-file> | ./node-functions.sh
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
    child_process.exec child_process.execSync \
    child_process.execFile child_process.execFileSync \
    child_process.spawn child_process.spawnSync \
    child_process.fork child_process

render "Code Execution" \
    eval new Function Function.constructor \
    vm.runInNewContext vm.runInThisContext vm.runInContext vm.Script \
    module._compile require "import()" global

render "Deserialization / Prototype Pollution" \
    JSON.parse qs.parse serialize-javascript node-serialize \
    lodash.merge lodash.defaultsDeep lodash.mergeWith

render "Filesystem" \
    fs.readFile fs.readFileSync fs.writeFile fs.writeFileSync \
    fs.appendFile fs.unlink fs.rename fs.chmod fs.chown \
    fs.readdir fs.readdirSync fs.createReadStream fs.createWriteStream \
    fs.open fs.stat fs.mkdir fs.rm

render "Network / SSRF" \
    net.createConnection net.Socket net.connect \
    http.get http.request https.get https.request \
    dgram.createSocket dns.lookup dns.resolve tls.connect \
    request.get axios.get fetch

render "Process / Env Disclosure" \
    process.env process.getuid process.getgid \
    os.hostname os.userInfo os.cpus os.networkInterfaces \
    os.homedir os.tmpdir process.version

render "Weak Crypto" \
    "crypto.createHash('md5')" "crypto.createHash('sha1')" \
    "crypto.createHmac('md5')" "crypto.createHmac('sha1')"

printf "\n${GRAY}Note: eval/new Function/require are built into the runtime and${RESET}\n"
printf "${GRAY}cannot be removed; the vm module is not a security boundary.${RESET}\n\n"

exit 0

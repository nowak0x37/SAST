#!/usr/bin/env bash
#
# ruby-functions.sh — given a list of Ruby methods/classes blocked by a
# sandbox (SafeLevel is gone, use $SAFE or a sandbox gem) or hardening
# checklist, report which dangerous primitives are still available.
#
# Usage:
#   ./ruby-functions.sh "Kernel.system,IO.popen"
#   ./ruby-functions.sh blocked.txt
#   blocked.txt | ./ruby-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./ruby-functions.sh "<blocked methods>"
  ./ruby-functions.sh <file-containing-the-list>
  <list-or-file> | ./ruby-functions.sh
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
    Kernel.system Kernel.exec "Kernel.\` (backtick)" \
    IO.popen Kernel.open Process.spawn \
    open3.popen3 open3.capture3 \
    Kernel.syscall

render "Code Execution" \
    Kernel.eval Kernel.load Kernel.require Kernel.autoload \
    Module.module_eval Module.class_eval \
    Object.instance_eval Object.send \
    Object.instance_variable_get Object.method_missing \
    Kernel.require_relative Binding.eval

render "Deserialization" \
    Marshal.load Marshal.restore Marshal.dump \
    YAML.load YAML.load_file Psych.load \
    Psych.unsafe_load Object.const_get

render "Reflection" \
    Kernel.const_get Object.const_get \
    Module.const_get ObjectSpace.each_object \
    Object.method Object.respond_to?

render "Filesystem" \
    File.open File.read File.write File.delete \
    File.rename File.chmod File.chown File.directory? \
    Dir.glob Dir.entries Dir.mkdir Dir.delete \
    FileUtils.rm_rf FileUtils.cp FileUtils.mv \
    Tempfile.new File.expand_path

render "Network / SSRF" \
    Net::HTTP.get Net::HTTP.start Net::HTTP.post_form \
    TCPSocket.new UDPSocket.new Socket.new \
    Net::FTP.open Net::SMTP.start \
    OpenURI.open_uri open-uri URI.open

render "System / Env Disclosure" \
    ENV.fetch ENV ENV.keys \
    Dir.pwd Dir.chdir Etc.getlogin Etc.getpwuid \
    Socket.gethostname Socket.getaddrinfo \
    Process.pid Process.uid Process.gid

render "Native / FFI" \
    Fiddle::Function Fiddle.dlopen \
    Fiddle::Importer FFI::Library ffi

printf "\n${GRAY}Note: Ruby \$SAFE / SafeLevel was removed; eval/load/send can${RESET}\n"
printf "${GRAY}only be constrained by a real sandbox like the rugged/Seccomp.${RESET}\n\n"

exit 0

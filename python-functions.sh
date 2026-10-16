#!/usr/bin/env bash
#
# python-functions.sh — given a list of functions blocked by a restricted
# Python sandbox (audit hooks, restricted exec, hardening checklist),
# report which dangerous primitives are still available.
#
# Usage:
#   ./python-functions.sh "os.system,subprocess.Popen"
#   ./python-functions.sh blocked.txt
#   blocked.txt | ./python-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./python-functions.sh "<blocked functions>"
  ./python-functions.sh <file-containing-the-list>
  <list-or-file> | ./python-functions.sh
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
    os.system os.popen os.popen2 os.popen3 os.popen4 \
    subprocess.Popen subprocess.run subprocess.call subprocess.check_call \
    subprocess.check_output subprocess.getoutput subprocess.getstatusoutput \
    pty.spawn commands.getoutput commands.getstatusoutput \
    os.execl os.execle os.execlp os.execv os.execve os.spawnl os.spawnv

render "Code Execution" \
    eval exec execfile compile input raw_input \
    __import__ importlib.import_module getattr setattr \
    globals locals vars apply map filter reduce \
    types.FunctionType code.CodeType sys.settrace sys.setprofile

render "Deserialization / Unsafe Parsing" \
    pickle.load pickle.loads pickle.Unpickler \
    cPickle.loads shelve.open marshal.load marshal.loads \
    yaml.load yaml.unsafe_load jsonpickle.decode \
    xml.etree.ElementTree.fromstring xml.dom.minidom.parse \
    xml.sax saxutils.parse

render "Filesystem" \
    open file os.open os.remove os.unlink os.rename os.chmod os.chown \
    os.mkdir os.makedirs os.rmdir os.listdir os.scandir os.walk os.stat \
    shutil.copy shutil.move shutil.rmtree tempfile.NamedTemporaryFile \
    pathlib.Path

render "Network / SSRF" \
    socket.socket urllib.urlopen urllib.request.urlopen urllib2.urlopen \
    urllib3 requests.get requests.post requests.request \
    http.client.HTTPConnection http.client.HTTPSConnection \
    ftplib.FTP telnetlib.Telnet smtplib.SMTP poplib.POP3 imaplib.IMAP4 \
    ssl.wrap_socket

render "System / Env Disclosure" \
    os.environ os.getenv os.getcwd os.chdir os.uname os.getuid os.getgid \
    getpass.getuser getpass.getpass platform.platform \
    sysconfig.get_config_vars socket.gethostname os.path.expanduser

render "Native / Module Loading" \
    ctypes.CDLL ctypes.util.find_library importlib reload imp dl

printf "\n${GRAY}Note: eval/exec/compile are builtins and cannot be removed${RESET}\n"
printf "${GRAY}from the interpreter; blocking needs audit hooks or a VM.${RESET}\n\n"

exit 0

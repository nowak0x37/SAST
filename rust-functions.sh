#!/usr/bin/env bash
#
# rust-functions.sh — given a list of Rust stdlib/crate functions blocked by
# a policy or hardening checklist, report which dangerous primitives are
# still available.
#
# Usage:
#   ./rust-functions.sh "std::process::Command,unsafe"
#   ./rust-functions.sh blocked.txt
#   blocked.txt | ./rust-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./rust-functions.sh "<blocked items>"
  ./rust-functions.sh <file-containing-the-list>
  <list-or-file> | ./rust-functions.sh
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
    std::process::Command std::process::Command::new \
    std::process::Command::output std::process::Command::spawn \
    std::os::unix::process::CommandExt::exec \
    libc::system libc::popen libc::execl libc::fork libc::execvp

render "Unsafe / FFI" \
    unsafe std::mem::transmute std::mem::forget \
    std::ptr::read std::ptr::write std::slice::from_raw_parts \
    std::ffi::CStr::from_ptr libc extern "C" \
    std::hint::unreachable_unchecked

render "Deserialization" \
    serde_json::from_str serde_yaml::from_str \
    bincode::deserialize rmp_serde::from_slice \
    serde::de::Deserialize toml::from_str

render "Filesystem" \
    std::fs::File std::fs::OpenOptions std::fs::read \
    std::fs::write std::fs::remove_file std::fs::remove_dir_all \
    std::fs::rename std::fs::set_permissions std::fs::read_dir \
    std::fs::create_dir_all std::path::Path

render "Network / SSRF" \
    std::net::TcpStream::connect std::net::TcpListener::bind \
    std::net::UdpSocket reqwest::blocking::get \
    reqwest::get hyper::Client::get url::Url::parse \
    std::net::ToSocketAddrs

render "System / Env Disclosure" \
    std::env::var std::env::vars std::env::current_dir \
    std::env::home_dir std::env::temp_dir \
    libc::getenv std::process::id std::env::set_var

render "Concurrency / Race Primitives" \
    std::thread::spawn std::sync::mpsc \
    std::sync::Arc std::sync::Mutex std::sync::RwLock \
    std::cell::RefCell std::rc::Rc

printf "\n${GRAY}Note: unsafe blocks let you bypass Rust's memory safety; treat${RESET}\n"
printf "${GRAY}any reachable unsafe or FFI call as a native code-exec primitive.${RESET}\n\n"

exit 0

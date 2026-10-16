#!/usr/bin/env bash
#
# java-functions.sh — given a list of classes/methods blocked by a Java
# security policy (or hardening checklist), report which dangerous
# primitives are still available.
#
# Usage:
#   ./java-functions.sh "java.lang.Runtime,ProcessBuilder"
#   ./java-functions.sh blocked.txt
#   blocked.txt | ./java-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./java-functions.sh "<blocked classes/methods>"
  ./java-functions.sh <file-containing-the-list>
  <list-or-file> | ./java-functions.sh
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
    java.lang.Runtime.exec java.lang.ProcessBuilder.start \
    java.lang.ProcessBuilder.command java.lang.ProcessImpl \
    java.lang.UNIXProcess sun.misc.Unsafe

render "Reflection" \
    java.lang.Class.forName java.lang.Class.getDeclaredMethod \
    java.lang.Class.getMethod java.lang.reflect.Method.invoke \
    java.lang.reflect.Constructor.newInstance \
    java.lang.reflect.Field.setAccessible \
    java.lang.reflect.AccessibleObject.setAccessible

render "Deserialization / RCE Gadgets" \
    java.io.ObjectInputStream.readObject \
    java.io.ObjectInputStream.readUnshared \
    java.beans.XMLDecoder.readObject \
    java.rmi.server.UnicastRemoteObject \
    java.rmi.registry.LocateRegistry.getRegistry \
    java.rmi.Naming.lookup javax.naming.InitialContext.lookup \
    javax.naming.directory.InitialDirContext \
    java.sql.DriverManager.getConnection

render "Script / Expression Engines" \
    javax.script.ScriptEngine.eval javax.script.ScriptEngineManager \
    groovy.lang.GroovyShell.evaluate bsh.Interpreter.eval \
    org.mvel2.MVEL.eval ognl.Ognl.getValue \
    org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression \
    freemarker.template.Template.process javax.el.ExpressionFactory

render "SSRF / Network" \
    java.net.URL.openConnection java.net.HttpURLConnection \
    java.net.http.HttpClient.send java.net.Socket \
    java.net.SocketChannel java.net.DatagramSocket java.net.InetAddress

render "Filesystem" \
    java.io.File java.io.FileInputStream java.io.FileOutputStream \
    java.nio.file.Files java.nio.file.Paths java.util.zip.ZipFile \
    java.util.zip.ZipOutputStream java.io.RandomAccessFile \
    java.nio.channels.FileChannel

render "JDBC / Data Access" \
    java.sql.DriverManager.getConnection \
    java.sql.Statement.execute java.sql.Statement.executeQuery \
    java.sql.PreparedStatement

render "System / Env Disclosure" \
    java.lang.System.getProperty java.lang.System.getenv \
    java.lang.Runtime.getRuntime java.lang.ProcessBuilder.environment \
    java.util.Properties java.lang.management.ManagementFactory.getRuntimeMXBean

render "JNI / Native" \
    java.lang.System.load java.lang.System.loadLibrary \
    java.lang.Runtime.loadLibrary

printf "\n${GRAY}Note: SecurityManager/System.setSecurityManager is deprecated and${RESET}\n"
printf "${GRAY}removed in modern JDKs; treat these as best-effort checks.${RESET}\n\n"

exit 0

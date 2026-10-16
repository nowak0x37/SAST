#!/usr/bin/env bash
#
# csharp-functions.sh — given a list of .NET APIs/assemblies restricted by
# a sandbox policy or hardening checklist, report which dangerous
# primitives are still available.
#
# Usage:
#   ./csharp-functions.sh "System.Diagnostics.Process,BinaryFormatter"
#   ./csharp-functions.sh blocked.txt
#   blocked.txt | ./csharp-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./csharp-functions.sh "<blocked types/methods>"
  ./csharp-functions.sh <file-containing-the-list>
  <list-or-file> | ./csharp-functions.sh
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
    System.Diagnostics.Process.Start \
    System.Diagnostics.ProcessStartInfo \
    System.Diagnostics.Process Microsoft.VisualBasic.Interaction.Shell

render "Reflection / Dynamic Code" \
    System.Reflection.Assembly.Load \
    System.Reflection.Assembly.LoadFrom \
    System.Reflection.Assembly.LoadFile \
    System.Reflection.Emit.DynamicMethod \
    System.Reflection.Emit.ILGenerator \
    AppDomain.CurrentDomain.DefineDynamicAssembly \
    System.Activator.CreateInstance System.Type.GetType \
    System.Linq.Expressions.Expression.Compile \
    System.CodeDom.Compiler.CodeDomProvider \
    Microsoft.CSharp.CSharpCodeProvider \
    System.Reflection.MethodInfo.Invoke

render "Deserialization" \
    System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize \
    System.Runtime.Serialization.Formatters.Soap.SoapFormatter.Deserialize \
    System.Web.UI.ObjectStateFormatter.Deserialize \
    System.Web.UI.LosFormatter.Deserialize \
    System.Runtime.Serialization.NetDataContractSerializer.ReadObject \
    System.Runtime.Serialization.DataContractSerializer.ReadObject \
    System.Xml.Serialization.XmlSerializer.Deserialize \
    System.Web.Script.Serialization.JavaScriptSerializer.DeserializeObject

render "Network / SSRF" \
    System.Net.WebClient System.Net.Http.HttpClient \
    System.Net.WebRequest System.Net.HttpWebRequest \
    System.Net.Sockets.TcpClient System.Net.Sockets.UdpClient \
    System.Net.Sockets.Socket System.Net.Mail.SmtpClient

render "Filesystem" \
    System.IO.File System.IO.FileInfo \
    System.IO.Directory System.IO.DirectoryInfo \
    System.IO.StreamReader System.IO.StreamWriter \
    System.IO.FileStream System.IO.Path

render "Data Access" \
    System.Data.SqlClient.SqlConnection \
    System.Data.OleDb.OleDbConnection \
    System.Data.Common.DbCommand.ExecuteReader \
    System.Data.SqlClient.SqlCommand.ExecuteNonQuery \
    System.Data.SqlClient.SqlCommand.ExecuteScalar

render "Weak Crypto" \
    System.Security.Cryptography.MD5 \
    System.Security.Cryptography.SHA1 \
    System.Security.Cryptography.DES \
    System.Security.Cryptography.RC2 \
    System.Security.Cryptography.TripleDES

render "Native / System Info" \
    System.Runtime.InteropServices.Marshal \
    System.Management.ManagementObjectSearcher \
    System.Environment.GetEnvironmentVariable \
    System.Environment.GetFolderPath

printf "\n${GRAY}Note: BinaryFormatter is marked obsolete/unsecure in modern .NET;${RESET}\n"
printf "${GRAY}any assembly loading API is a code-exec primitive.${RESET}\n\n"

exit 0

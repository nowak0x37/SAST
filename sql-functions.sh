#!/usr/bin/env bash
#
# sql-functions.sh — given a list of SQL statements/procedures/features
# blocked by a hardened DBMS configuration, report which dangerous
# capabilities are still available.
#
# Usage:
#   ./sql-functions.sh "xp_cmdshell,LOAD DATA INFILE"
#   ./sql-functions.sh blocked.txt
#   blocked.txt | ./sql-functions.sh

set -u

BOLD_RED=$'\e[1;31m'
BOLD_WHITE=$'\e[1;37m'
GRAY=$'\e[3;37m'
RESET=$'\e[0m'

usage() {
    cat <<'EOF'
Usage:
  ./sql-functions.sh "<blocked statements>"
  ./sql-functions.sh <file-containing-the-list>
  <list-or-file> | ./sql-functions.sh
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

render "Command Execution (MSSQL)" \
    xp_cmdshell sp_oacreate sp_oamethod sp_oagetproperty \
    sp_oasetproperty sp_oadestroy sp_makewebtask \
    sp_send_dbmail master..xp_cmdshell \
    xp_regread xp_regwrite xp_regdeletevalue

render "Command Execution (Oracle)" \
    utl_file utl_http utl_smtp utl_tcp \
    dbms_scheduler.create_job dbms_scheduler.run_job \
    dbms_java.runjava dbms_ldap.init \
    java.lang.Runtime.getRuntime

render "Command Execution (Postgres)" \
    COPY ... TO PROGRAM pg_read_file pg_write_file \
    pg_ls_dir lo_import lo_export \
    dblink_connect dblink_exec

render "Command Execution (MySQL / MariaDB)" \
    sys_exec sys_eval LOAD DATA INFILE LOAD_FILE \
    INTO OUTFILE SELECT ... INTO OUTFILE \
    user_defined_function

render "Privilege Escalation" \
    GRANT ALL GRANT SUPER GRANT FILE GRANT EXECUTE \
    ALTER USER SET PASSWORD SET ROLE \
    TRUNCATE DROP DATABASE

render "Information Disclosure" \
    INFORMATION_SCHEMA.TABLES INFORMATION_SCHEMA.COLUMNS \
    SHOW DATABASES SHOW TABLES SHOW GRANTS \
    SELECT * FROM mysql.user SELECT * FROM sys.user \
    pg_settings pg_stat_activity "v\$session"

render "Filesystem / Out-of-Band" \
    INTO OUTFILE INTO DUMPFILE UTL_FILE.FOPEN \
    BULK INSERT OPENROWSET OPENQUERY \
    SELECT ... INTO OUTFILE FILE

render "Weak Config / Dangerous" \
    SET GLOBAL general_log SET GLOBAL slow_query_log \
    secure_file_priv off \
    TRUSTED_ROOT_CERTIFICATE \
    allow_native_password

printf "\n${GRAY}Note: most DBMS gate RCE behind privileges; the real risk is${RESET}\n"
printf "${GRAY}when a web app passes unsanitized input into these statements.${RESET}\n\n"

exit 0

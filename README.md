Quick-fire audit scripts that tell you **which dangerous functions are still
available** after a hardening policy has blocked a list of functions, classes,
cmdlets, or statements.

Feed in the "blocked" list (comma separated, a file, or via stdin), and the
script prints every high-risk primitive that survived the blocklist, grouped
by category.

---

## What it does

These tools are the inverse of a deny-list checker. Given the set of functions
an application (or its sandbox / security policy) has disabled, they answer the
question that actually matters to a pentester or defender:

> **What can I still do?**

The output is grouped into categories such as *Command Execution*, *Code
Execution*, *Deserialization*, *Filesystem*, and *SSRF / Network*.

Works with:

```
./php-functions.sh "system,exec,shell_exec"
```

```
cat disabled.txt | ./php-functions.sh
```

```
./php-functions.sh disabled.txt
```

---

## Scripts

| Script | Target | Highlights |
| --- | --- | --- |
| `php-functions.sh` | PHP `disable_functions` | `system`, `exec`, `shell_exec`, `assert`, `preg_replace`, `proc_open`, `phpinfo` |
| `python-functions.sh` | Python sandbox / audit hooks | `os.system`, `subprocess.*`, `eval`, `exec`, `pickle`, `ctypes` |
| `java-functions.sh` | Java security policy | `Runtime.exec`, `ProcessBuilder`, reflection, JNDI, deserialization, JDBC |
| `csharp-functions.sh` | .NET sandbox / policy | `Process.Start`, `Assembly.Load`, `BinaryFormatter`, `HttpClient`, weak crypto |
| `node-functions.sh` | Node.js sandbox / policy | `child_process.*`, `eval`, `new Function`, `vm`, `fs`, prototype pollution |
| `go-functions.sh` | Go stdlib policy | `os/exec`, `unsafe`, cgo/FFI, `net/*`, `database/sql` |
| `ruby-functions.sh` | Ruby sandbox / gems | `Kernel.system`, backticks, `eval`, `send`, `Marshal`, `YAML`, `Net::HTTP` |
| `rust-functions.sh` | Rust policy | `std::process::Command`, `unsafe`, FFI, `serde`, `std::net` |
| `powershell-functions.sh` | PowerShell policy / CLM | `Invoke-Expression`, `Add-Type`, deserialization, `Invoke-WebRequest`, AD |
| `sql-functions.sh` | MSSQL / Oracle / PG / MySQL | `xp_cmdshell`, `utl_file`, `COPY TO PROGRAM`, `LOAD DATA INFILE` |
| `bash-functions.sh` | restricted shell / rbash | `eval`, command substitution, network tools, privilege escalation |
| `perl-functions.sh` | Perl taint / policy | `system`, backticks, `eval`, `Storable`, sockets, FFI |

---

## Features

- **Namespace-aware matching** — blocking a module/namespace suppresses
  everything under it:
  - `os/exec` removes `os/exec.Command`, `os/exec.CommandContext`, ...
  - `java.lang` removes `java.lang.Runtime.exec`, `java.lang.Class.forName`, ...
  - `Net::` removes `Net::FTP`, `Net::SMTP`, ...
- **Case-insensitive** matching (PHP/Node/etc.), so `PCNTL_EXEC` correctly
  disables `pcntl_exec`.
- **Three input modes**: inline argument, path to a file, or stdin.
- **Messy input tolerant** — handles spaces after commas and `;` separators.
- **Color-coded** output, grouped by attack category.
- `set -u` and no temp files — input is processed entirely in memory.

---

## Requirements

- `bash` 4.0+ (for associative arrays and `mapfile`)
- Standard POSIX utilities: `tr`, `sed`, `tput` (optional)

---

## Usage

All scripts share the same interface.

### 1. Inline list

```bash
./php-functions.sh "system,exec,shell_exec,proc_open"
```

### 2. From a file

```bash
./python-functions.sh disabled.txt
```

### 3. Piped from a command

```bash
curl -s http://target/phpinfo-disabled.txt | ./php-functions.sh
```

### Example output

```text
----------------------------------------------------------------------------
system,exec,shell_exec
----------------------------------------------------------------------------

# Command Execution Functions #
   * passthru - enabled
   * pcntl_exec - enabled
   * popen - enabled
   * proc_open - enabled

# PHP Code Execution Functions #
   * assert - enabled
   * preg_replace - enabled
   ...
```

---

## How matching works

The input is normalized (separators → whitespace → lowercase) and matched
against every function in the audit list. A function is reported as
*enabled/available* only if **neither it nor any parent namespace** is in the
blocked set.

| Blocked input | Suppresses |
| --- | --- |
| `os.system` | `os.system` only |
| `os` | `os.*`, `os.popen`, `os.environ`, ... |
| `java.lang` | `java.lang.*` |
| `std::fs` | `std::fs::*` |
| `child_process` | `child_process.*` |

---

## Customization

Each script keeps its audit list in a `render "Category Name" \` block. To add
or remove checks, just edit the list:

```bash
render "Command Execution Functions" \
    system exec passthru pcntl_exec popen pclose \
    proc_open proc_close proc_get_status proc_terminate shell_exec
```

Add your own entries or drop whole categories — the render loop handles any
number of items.

---

## Notes & caveats

- Several "functions" are language constructs (`include`, `require`, `eval`,
  `import`) and **cannot** be disabled via `disable_functions`; the scripts
  note this where relevant.
- Execution policies, taint mode, and `vm`/sandbox modules are **not** security
  boundaries by themselves — treat them as defense-in-depth, and confirm real
  controls (seccomp, CLM, AppLocker/WDAC, audit hooks) are in place.
- PHP function names are case-insensitive; the scripts normalize input to
  lowercase so case differences can't be used to bypass the audit.

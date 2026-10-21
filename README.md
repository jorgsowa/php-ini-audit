# php-ini-audit

> [!WARNING]
> **Work in progress.** This project is under active development and has not been released yet. Rules,
> severities, the CLI and the report formats may change without notice. Review findings before acting on
> them, and report false positives or missed issues in the issue tracker.

Static security audit of PHP INI configuration: `php.ini`, scan-dir `conf.d/*.ini`, PHP-FPM pools,
`.user.ini` and `.htaccess` PHP directives.

Documentation: https://jorgsowa.github.io/php-ini-audit/

It reports **every** rule that matches, each with its own severity and confidence, and shows where the
effective value came from (file and line, or PHP's built-in default). It never gives a single pass/fail verdict.

## Safety

- **Nothing is executed.** No `php -i`, no subprocesses, no `eval`, no network access. A test
  (`tests/test_safety.py`) fails the build if such primitives are introduced.
- Files are only read: regular files only (no FIFOs or devices), up to 4 MiB, binary content rejected.
- With `--root`, symlinks are resolved inside the root, so a link to `/etc/shadow` in an image cannot escape it.
- Path checks only call `stat()`. `${ENV}` references are never expanded; they are reported instead.
- Pure standard library (Python ≥ 3.9), no dependencies.

## Install

```sh
pip install .            # or: pipx install .
php-ini-audit --help
```

Without installing: `PYTHONPATH=src python3 -m php_ini_audit ...`

## Usage

```sh
php-ini-audit                                  # discover and audit installations on this host
php-ini-audit /etc/php/8.3/fpm/php.ini         # one file (sibling conf.d/ and pool.d/ are picked up)
php-ini-audit ./config-backup/                 # walk a directory of copied configs
php-ini-audit --root /mnt/container-rootfs     # audit an extracted image / chroot / mounted disk
php-ini-audit --webroot /var/www/html          # also audit .user.ini/.htaccess below the docroot
php-ini-audit --ini custom.ini --scan-dir conf.d --pool www.conf
php-ini-audit discover                         # only list what would be read
php-ini-audit rules                            # rule catalogue; `rules SESS-001` explains one rule
```

Useful options:

| Option | Purpose |
| --- | --- |
| `--profile production\|development` | Development lowers disclosure findings and skips production-only rules |
| `--sapi`, `--php-version` | Override what is inferred from the path (`/etc/php/8.2/fpm/` → fpm, 8.2) |
| `--path-checks auto\|on\|off` | Permission checks on referenced paths; `auto` = on for host and `--root` scans |
| `--min-severity`, `--only`, `--skip` | Filter by severity, rule id or category (`--only SESS --skip SESS-012`) |
| `--format text\|json\|sarif\|markdown`, `-o FILE` | SARIF works with GitHub code scanning |
| `--fail-on SEVERITY` | Exit 1 when a finding at or above SEVERITY exists (default: always exit 0) |

## How it works

1. **Discovery** looks for `php.ini` in the locations used by Debian/Ubuntu, RHEL/Remi, Alpine, Arch, SUSE,
   FreeBSD, official Docker images, Homebrew, cPanel EasyApache, Plesk, CloudLinux, XAMPP, MAMP, Bitnami and
   common Windows bundles, together with their scan directories and PHP-FPM pools. A directory with
   `php.ini-production` but no `php.ini` (the official Docker image layout) is reported as running on
   built-in defaults.
2. **Parsing** follows PHP's INI grammar: `;` comments, quoting, `On/Off/None` keywords,
   `error_reporting` expressions (evaluated without `eval`), `[PATH=]/[HOST=]` sections, multi-line quoted values.
3. **Layering** reproduces PHP's order: php.ini, then scan-dir files alphabetically. FPM pools,
   `.user.ini`, `.htaccess` and `[PATH=]` sections are evaluated as overlays on top of their base. Overlays
   respect changeability modes: `disable_functions` in `.user.ini` is reported as ignored, not as applied.
   `php_admin_value[disable_functions]` appends, as PHP-FPM does.
4. **Rules** run against each effective configuration. Unset directives are checked against PHP's
   built-in defaults, which is where many real problems come from (`display_errors`, `register_argc_argv`,
   `session.use_strict_mode`, ...). Web-only rules are skipped for CLI configurations.

Each finding carries a severity (critical → info), a confidence (high/medium/low), the effective value and
its source, a CWE where applicable and a recommendation.

## Rules

| Rule | Severity | Category | Title |
| --- | --- | --- | --- |
| CFG-001 | low | Configuration hygiene | Syntax problem in configuration file |
| CFG-002 | info | Configuration hygiene | Obsolete directive |
| CFG-003 | low | Configuration hygiene | Unknown directive resembling a known one |
| CFG-004 | info | Configuration hygiene | Directive redefined with a different value |
| CFG-005 | low | Configuration hygiene | Per-directory override that PHP ignores |
| CFG-006 | medium | Configuration hygiene | No php.ini loaded: built-in defaults in effect |
| CFG-007 | info | Configuration hygiene | Value depends on an environment variable |
| CFG-008 | low | Configuration hygiene | Development configuration used in production |
| CFG-009 | info | Configuration hygiene | Conditional [PATH=]/[HOST=] section |
| CFG-010 | info | Configuration hygiene | Deprecated directive |
| CGI-001 | high | CGI / FastCGI | php-cgi callable without web-server redirect |
| CGI-002 | medium | CGI / FastCGI | PATH_INFO fix-up executes files by path prefix |
| DB-001 | medium | Database and credentials | MySQL LOAD DATA LOCAL enabled |
| DB-002 | medium | Database and credentials | Credentials stored in PHP configuration |
| DB-003 | low | Database and credentials | SQLite safety features relaxed |
| ENC-001 | medium | Character encoding | Unsafe default character set |
| ENC-002 | medium | Character encoding | mbstring function overloading enabled |
| ENC-003 | low | Character encoding | Multibyte script parsing enabled |
| ENC-004 | low | Character encoding | Automatic input encoding translation |
| ERR-001 | medium | Information disclosure | Errors displayed to visitors |
| ERR-002 | low | Information disclosure | Start-up errors displayed |
| ERR-003 | low | Information disclosure | Errors are not logged |
| ERR-004 | low | Information disclosure | PHP version disclosed in HTTP headers |
| ERR-005 | low | Information disclosure | Function arguments included in stack traces |
| ERR-006 | low | Information disclosure | Error reporting disabled |
| ERR-007 | low | Information disclosure | Script path added to outgoing mail headers |
| ERR-008 | low | Information disclosure | Environment variables copied into $_ENV |
| ERR-009 | low | Information disclosure | Error log created world-writable |
| ERR-010 | info | Information disclosure | phpinfo() callable |
| ERR-011 | info | Information disclosure | Long string arguments kept in stack traces |
| EXEC-001 | critical | Code execution | Remote file inclusion enabled |
| EXEC-002 | medium | Code execution | Remote URLs accepted by file functions |
| EXEC-003 | critical | Code execution | Auto-prepended/appended file loaded through a stream wrapper |
| EXEC-004 | info | Code execution | Code automatically prepended or appended to every script |
| EXEC-005 | medium | Code execution | Command execution functions are available |
| EXEC-006 | medium | Code execution | disable_functions can be bypassed |
| EXEC-007 | high | Code execution | FFI available to every script |
| EXEC-008 | low | Code execution | Runtime extension loading (dl) enabled |
| EXEC-009 | medium | Code execution | Phar archives writable at runtime |
| EXEC-010 | low | Code execution | Unsigned Phar archives accepted |
| EXEC-011 | medium | Code execution | Query string exposed as $argv in web requests |
| EXEC-012 | high | Code execution | imap_open() may run rsh/ssh commands |
| EXEC-013 | high | Code execution | Dangerous sendmail options configured |
| EXEC-014 | low | Code execution | Assertions compiled and executed in production |
| EXEC-015 | low | Code execution | Callback invoked when unserialize() meets an unknown class |
| EXEC-016 | info | Code execution | include_path contains the current directory |
| EXEC-017 | low | Code execution | Session upload progress writes request data into session files |
| EXT-001 | critical | Debug and profiling extensions | Xdebug accepts debugger connections for any client |
| EXT-002 | high | Debug and profiling extensions | Xdebug loaded |
| EXT-003 | low | Debug and profiling extensions | Development or profiling extension loaded |
| FPM-001 | critical | PHP-FPM pools | FastCGI port reachable from the network |
| FPM-002 | high | PHP-FPM pools | Non-PHP files executable by the pool |
| FPM-003 | medium | PHP-FPM pools | FastCGI socket writable by every user |
| FPM-004 | high | PHP-FPM pools | Pool workers run as root |
| FPM-005 | low | PHP-FPM pools | Status or ping endpoint enabled |
| FPM-006 | low | PHP-FPM pools | Full environment passed to PHP |
| FPM-007 | medium | PHP-FPM pools | Secret stored in pool configuration |
| FPM-008 | low | PHP-FPM pools | Workers are dumpable |
| FS-001 | medium | Filesystem and paths | open_basedir is not set |
| FS-002 | medium | Filesystem and paths | open_basedir allows the whole filesystem |
| FS-003 | low | Filesystem and paths | open_basedir entries match by prefix |
| FS-004 | low | Filesystem and paths | open_basedir uses relative entries |
| FS-005 | high | Filesystem and paths | Security-relevant path is world-writable |
| FS-006 | high | Filesystem and paths | Sensitive path inside a web-served directory |
| FS-007 | info | Filesystem and paths | Configured path does not exist |
| FS-008 | info | Filesystem and paths | Per-directory .user.ini overrides enabled |
| FS-009 | info | Filesystem and paths | HTTP file uploads enabled |
| FS-010 | info | Filesystem and paths | Uploads stored in the shared system temp directory |
| FS-011 | critical | Filesystem and paths | Configuration file writable by other users |
| HTA-001 | high | Apache .htaccess | Non-PHP files mapped to the PHP handler |
| OPC-001 | medium | OPcache | OPcache file cache enabled |
| OPC-002 | low | OPcache | OPcache API not restricted |
| OPC-003 | info | OPcache | OPcache does not isolate users |
| RES-001 | medium | Resource limits and DoS | Unlimited or very large memory_limit |
| RES-002 | medium | Resource limits and DoS | Unlimited or long max_execution_time |
| RES-003 | medium | Resource limits and DoS | Unlimited or very large POST bodies |
| RES-004 | low | Resource limits and DoS | Very large uploads accepted |
| RES-005 | low | Resource limits and DoS | max_input_vars raised or disabled |
| RES-006 | low | Resource limits and DoS | Deep input nesting allowed |
| RES-007 | low | Resource limits and DoS | Many files per request accepted |
| RES-008 | low | Resource limits and DoS | Regular expression limits raised |
| RES-009 | low | Resource limits and DoS | unserialize() nesting depth unlimited |
| RES-010 | low | Resource limits and DoS | Socket reads may block indefinitely |
| RES-011 | low | Resource limits and DoS | Unlimited multipart body parts |
| SESS-001 | medium | Session security | Uninitialised session IDs accepted |
| SESS-002 | high | Session security | Session IDs accepted outside cookies |
| SESS-003 | high | Session security | Transparent session IDs in URLs |
| SESS-004 | medium | Session security | Session cookies disabled |
| SESS-005 | medium | Session security | Session cookie readable from JavaScript |
| SESS-006 | medium | Session security | Session cookie sent over plain HTTP |
| SESS-007 | low | Session security | Session cookie without SameSite protection |
| SESS-008 | high | Session security | Weak session ID entropy |
| SESS-009 | medium | Session security | Session files stored in a shared or listable directory |
| SESS-010 | medium | Session security | Session files created with permissive mode |
| SESS-011 | low | Session security | Long-lived sessions |
| SESS-012 | info | Session security | Default session cookie name |
| SESS-013 | info | Session security | Persistent session cookie |
| SESS-014 | info | Session security | Session cookie shared with other hosts |

Regenerate this table with `php-ini-audit rules --format markdown`.

## Limitations

- Static analysis sees configuration files only. It cannot see `-d` command-line flags, `PHP_INI_SCAN_DIR`
  or `PHP_VALUE` set by a web server, `ini_set()` calls, or which extensions are compiled in.
- Directives from Apache vhost files (`php_admin_value` in `httpd.conf`) are not parsed; `.htaccess` is.
- Web-root detection is heuristic unless `--webroot` is given.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -t .
```

The documentation site is plain HTML in `docs/`, deployed to GitHub Pages by `.github/workflows/pages.yml`
(set Pages → Source to "GitHub Actions"). The rule reference and counts are generated from the rule registry:

```sh
python3 scripts/build_docs.py           # refresh docs/*.html
python3 scripts/build_docs.py --check   # fail if out of date (also covered by the test suite)
```

Rules live in `src/php_ini_audit/rules/`. Each one is a generator registered with `@rule(...)` that yields
`Hit`s, so one rule can report several problems at different severities.

## License

[MIT](LICENSE)

# php-ini-audit

> [!WARNING]
> **Work in progress.** Rules, severities, the CLI and report formats may change without notice.

Static, read-only security audit of PHP INI configuration: `php.ini`, `conf.d/*.ini`, PHP-FPM pools,
`.user.ini` and `.htaccess`. Nothing is executed. Python ≥ 3.9, no dependencies.

Full documentation and rule reference: https://jorgsowa.github.io/php-ini-audit/

## Install

```sh
pip install .
```

Or run without installing: `PYTHONPATH=src python3 -m php_ini_audit`

## Run

```sh
php-ini-audit                                # audit PHP installations on this host
php-ini-audit /etc/php/8.3/fpm/php.ini       # audit one file
php-ini-audit --root /mnt/container-rootfs   # audit an extracted image or mounted disk
php-ini-audit --format sarif -o report.sarif # SARIF for GitHub code scanning
php-ini-audit --fail-on high                 # exit 1 on high or critical findings
```

`php-ini-audit --help` lists all options; `php-ini-audit rules` lists the rules.

## Test

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -t .
```

## License

[MIT](LICENSE)

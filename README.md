# php-ini-audit

> [!WARNING]
> **Work in progress.** Rules, severities, the CLI and report formats may change without notice.

Static, read-only security audit of PHP INI configuration: `php.ini`, `conf.d/*.ini`, PHP-FPM pools,
`.user.ini` and `.htaccess`. Nothing is executed. PHP ≥ 7.4, core extensions only.

Full documentation and rule reference: https://jorgsowa.github.io/php-ini-audit/

## Install

```sh
composer global require jorgsowa/php-ini-audit
```

Or run from a checkout: `bin/php-ini-audit`. To get one file to copy onto a server:

```sh
php -d phar.readonly=0 scripts/build_phar.php   # writes build/php-ini-audit.phar
```

## Run

```sh
php-ini-audit                                # audit PHP installations on this host
php-ini-audit /etc/php/8.3/fpm/php.ini       # audit one file
php-ini-audit --root /mnt/container-rootfs   # audit an extracted image or mounted disk
php-ini-audit --format sarif -o report.sarif # SARIF for GitHub code scanning
php-ini-audit --fail-on high                 # exit 1 on high or critical findings
php-ini-audit --group-by rule                # each rule once, with the configs it affects
php-ini-audit --summary                      # one line of severity counts
php -i | php-ini-audit --phpinfo -           # audit the values a running PHP reports
```

Or paste `phpinfo()` output, php.ini, a PHP-FPM pool or .htaccess into the
[browser scanner](https://jorgsowa.github.io/php-ini-audit/scan.html); nothing is uploaded.

`php-ini-audit --help` lists all options; `php-ini-audit rules` lists the rules.

## Test

```sh
composer install
vendor/bin/phpunit
```

## License

[MIT](LICENSE)

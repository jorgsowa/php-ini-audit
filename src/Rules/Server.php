<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Directive;
use PhpIniAudit\FpmPool;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;
use PhpIniAudit\Values;

/** CGI/FastCGI settings, PHP-FPM pools and Apache handler mappings. */
final class Server
{
    public const PHP_EXTENSIONS = ['.php', '.php3', '.php4', '.php5', '.php7', '.php8', '.phtml', '.phar'];
    private const NON_PHP_PATTERN =
        '/jpe?g|png|gif|bmp|webp|svg|ico|txt|html?|css|js|json|xml|pdf|zip|docx?|xlsx?|csv|mp[34]|\.\*|^\.$|^\*$/i';
    private const SECRET_NAME = '/pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential/i';
    private const LOOPBACK = '/^(127\.\d+\.\d+\.\d+|::1|\[::1\]|localhost)$/i';

    /** @return array{?Directive, ?list<string>} */
    private static function limitExtensions(FpmPool $pool): array
    {
        $directive = $pool->settings['security.limit_extensions'] ?? null;
        if ($directive === null) {
            return [null, null];
        }
        return [$directive, array_map('strtolower', Values::splitList($directive->value))];
    }

    private static function isPhpExtension(string $extension): bool
    {
        return in_array($extension, self::PHP_EXTENSIONS, true);
    }

    public static function register(): void
    {
        Registry::rule('CGI-001', 'php-cgi callable without web-server redirect', [
            'severity' => Severity::HIGH,
            'directives' => ['cgi.force_redirect'],
            'sapis' => ['cgi', 'unknown'],
            'cwe' => 'CWE-88',
            'description' => 'cgi.force_redirect = 0 lets php-cgi be invoked directly, the precondition for argument '
                . 'injection such as CVE-2012-1823 and CVE-2024-4577.',
            'recommendation' => 'Keep cgi.force_redirect = 1 (only IIS needs it off), or move to PHP-FPM.',
            'references' => [
                'https://nvd.nist.gov/vuln/detail/CVE-2012-1823',
                'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
            ],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('cgi.force_redirect');
            if ($setting->asBool()) {
                return;
            }
            if ($ctx->sapi === 'cgi') {
                yield new Hit('cgi.force_redirect is Off for php-cgi', [$setting]);
            } else {
                yield new Hit(
                    'cgi.force_redirect is Off (matters if this config serves php-cgi)',
                    [$setting],
                    Severity::MEDIUM,
                    Confidence::LOW
                );
            }
        });

        Registry::rule('CGI-002', 'PATH_INFO fix-up executes files by path prefix', [
            'severity' => Severity::MEDIUM,
            'directives' => ['cgi.fix_pathinfo'],
            'sapis' => Base::FASTCGI_SAPIS,
            'cwe' => 'CWE-434',
            'description' => 'With cgi.fix_pathinfo = 1 a request for /uploads/avatar.jpg/x.php can make PHP execute '
                . "avatar.jpg when the web server forwards any *.php path. PHP-FPM's security.limit_extensions "
                . 'blocks it.',
            'recommendation' => 'Set cgi.fix_pathinfo = 0, or make sure the web server checks that the script '
                . 'exists (try_files $fastcgi_script_name =404) and security.limit_extensions = .php.',
            'references' => ['https://nvd.nist.gov/vuln/detail/CVE-2019-11043'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('cgi.fix_pathinfo');
            if (!$setting->asBool()) {
                return;
            }
            if ($ctx->sapi === 'fpm' || $ctx->pools) {
                $restricted = true;
                foreach ($ctx->pools as $pool) {
                    [, $exts] = self::limitExtensions($pool);
                    if ($exts !== null && (!$exts || array_diff($exts, self::PHP_EXTENSIONS))) {
                        $restricted = false;
                        break;
                    }
                }
                if ($restricted) {
                    yield new Hit(
                        'cgi.fix_pathinfo = 1; mitigated by security.limit_extensions in PHP-FPM',
                        [$setting],
                        Severity::LOW
                    );
                    return;
                }
            }
            yield new Hit('cgi.fix_pathinfo = 1', [$setting], null, Confidence::MEDIUM);
        });

        Registry::rule('FPM-001', 'FastCGI port reachable from the network', [
            'severity' => Severity::CRITICAL,
            'scope' => 'pool',
            'cwe' => 'CWE-306',
            'description' => 'FastCGI has no authentication. Anyone who reaches the port can pass PHP_VALUE / '
                . 'PHP_ADMIN_VALUE (e.g. auto_prepend_file = php://input) and execute code.',
            'recommendation' => 'Listen on a Unix socket or 127.0.0.1, and set listen.allowed_clients; never publish '
                . 'the port outside the host or container network.',
        ], static function (Context $ctx): iterable {
            $listen = $ctx->pool->settings['listen'] ?? null;
            if ($listen === null) {
                return;
            }
            $address = trim($listen->value);
            if (Util::startsWith($address, '/') || $address === '') {
                return;
            }
            if (ctype_digit($address)) {
                $host = '*';
            } else {
                $colon = strrpos($address, ':');
                $host = $colon !== false ? substr($address, 0, $colon) : $address;
            }
            $host = trim($host);
            if (preg_match(self::LOOPBACK, $host)) {
                return;
            }
            $allowed = $ctx->pool->settings['listen.allowed_clients'] ?? null;
            $allInterfaces = in_array($host, ['*', '0.0.0.0', '[::]', '::'], true);
            if ($allowed !== null && trim($allowed->value) !== '') {
                yield new Hit(
                    "listen = $address; restricted by listen.allowed_clients = {$allowed->value}",
                    [$listen, $allowed],
                    Severity::MEDIUM
                );
            } elseif ($allInterfaces) {
                yield new Hit(
                    "listen = $address binds every interface without listen.allowed_clients",
                    [$listen],
                    null,
                    Confidence::MEDIUM
                );
            } else {
                yield new Hit("listen = $address without listen.allowed_clients", [$listen], Severity::HIGH,
                    Confidence::MEDIUM);
            }
        });

        Registry::rule('FPM-002', 'Non-PHP files executable by the pool', [
            'severity' => Severity::HIGH,
            'scope' => 'pool',
            'cwe' => 'CWE-434',
            'description' => 'security.limit_extensions restricts which files FPM will execute. An empty list or '
                . 'image/text extensions turn uploaded files into code.',
            'recommendation' => 'Use security.limit_extensions = .php',
        ], static function (Context $ctx): iterable {
            [$directive, $exts] = self::limitExtensions($ctx->pool);
            if ($directive === null) {
                return;
            }
            if (!$exts) {
                yield new Hit('security.limit_extensions is empty: every file may be executed', [$directive]);
                return;
            }
            $extra = array_values(array_filter($exts, static function (string $e): bool {
                return !self::isPhpExtension($e);
            }));
            if ($extra) {
                yield new Hit('security.limit_extensions allows ' . Base::names($extra), [$directive]);
            }
        });

        Registry::rule('FPM-003', 'FastCGI socket writable by every user', [
            'severity' => Severity::MEDIUM,
            'scope' => 'pool',
            'cwe' => 'CWE-276',
            'description' => 'A world-writable FPM socket lets any local user send FastCGI requests and run code as '
                . 'the pool user.',
            'recommendation' => 'Use listen.mode = 0660 with listen.owner/listen.group set to the web server.',
        ], static function (Context $ctx): iterable {
            $directive = $ctx->pool->settings['listen.mode'] ?? null;
            if ($directive === null) {
                return;
            }
            $mode = Values::parseOctal($directive->value);
            if ($mode !== null && ($mode & 0002)) {
                yield new Hit("listen.mode = {$directive->value}", [$directive]);
            }
        });

        Registry::rule('FPM-004', 'Pool workers run as root', [
            'severity' => Severity::HIGH,
            'scope' => 'pool',
            'cwe' => 'CWE-250',
            'description' => 'Running PHP as root turns any application bug into full system compromise.',
            'recommendation' => 'Run each pool as a dedicated unprivileged user and group.',
        ], static function (Context $ctx): iterable {
            foreach (['user', 'group'] as $key) {
                $directive = $ctx->pool->settings[$key] ?? null;
                if ($directive !== null && in_array(trim($directive->value), ['root', '0'], true)) {
                    yield new Hit("$key = {$directive->value}", [$directive]);
                }
            }
        });

        Registry::rule('FPM-005', 'Status or ping endpoint enabled', [
            'severity' => Severity::LOW,
            'scope' => 'pool',
            'cwe' => 'CWE-200',
            'description' => 'pm.status_path and ping.path expose pool internals (client IPs, request URIs) if the '
                . 'web server forwards them.',
            'recommendation' => 'Remove them or restrict access in the web server.',
        ], static function (Context $ctx): iterable {
            foreach (['pm.status_path', 'ping.path'] as $key) {
                $directive = $ctx->pool->settings[$key] ?? null;
                if ($directive !== null && trim($directive->value) !== '') {
                    yield new Hit("$key = {$directive->value}", [$directive], null, Confidence::MEDIUM);
                }
            }
        });

        Registry::rule('FPM-006', 'Full environment passed to PHP', [
            'severity' => Severity::LOW,
            'scope' => 'pool',
            'cwe' => 'CWE-526',
            'description' => 'clear_env = no gives PHP every environment variable of the FPM master.',
            'recommendation' => 'Keep clear_env = yes and pass only needed variables with env[NAME].',
        ], static function (Context $ctx): iterable {
            $directive = $ctx->pool->settings['clear_env'] ?? null;
            if ($directive !== null && !Values::toBool($directive->value)) {
                yield new Hit('clear_env = no', [$directive]);
            }
        });

        Registry::rule('FPM-007', 'Secret stored in pool configuration', [
            'severity' => Severity::MEDIUM,
            'scope' => 'pool',
            'cwe' => 'CWE-260',
            'description' => 'Literal secrets in env[] entries end up in configuration backups and in '
                . 'phpinfo()/$_SERVER.',
            'recommendation' => 'Reference the master environment (env[DB_PASSWORD] = $DB_PASSWORD) or use a secret '
                . 'store.',
        ], static function (Context $ctx): iterable {
            foreach ($ctx->pool->env as $directive) {
                if (preg_match(self::SECRET_NAME, $directive->name) && $directive->value !== ''
                    && !Util::startsWith($directive->value, '$')) {
                    yield new Hit("env[{$directive->name}] holds a literal value", [$directive], null,
                        Confidence::MEDIUM);
                }
            }
        });

        Registry::rule('FPM-008', 'Workers are dumpable', [
            'severity' => Severity::LOW,
            'scope' => 'pool',
            'cwe' => 'CWE-528',
            'description' => 'process.dumpable = yes allows core dumps and ptrace of workers by the same user, '
                . 'exposing secrets held in memory.',
            'recommendation' => 'Keep process.dumpable = no.',
        ], static function (Context $ctx): iterable {
            $directive = $ctx->pool->settings['process.dumpable'] ?? null;
            if ($directive !== null && Values::toBool($directive->value)) {
                yield new Hit('process.dumpable = yes', [$directive]);
            }
        });

        Registry::rule('HTA-001', 'Non-PHP files mapped to the PHP handler', [
            'severity' => Severity::HIGH,
            'scope' => 'file',
            'cwe' => 'CWE-434',
            'description' => 'AddType/AddHandler/SetHandler mapping images, text or every file to PHP makes uploads '
                . 'executable.',
            'recommendation' => 'Map only .php to the PHP handler, inside <FilesMatch "\\.php$">.',
        ], static function (FileContext $fctx): iterable {
            $handlers = property_exists($fctx->file, 'handlers') ? $fctx->file->handlers : [];
            foreach ($handlers as $mapping) {
                if ($mapping->extensions) {
                    $extra = array_values(array_filter($mapping->extensions, static function (string $e): bool {
                        return !self::isPhpExtension('.' . ltrim($e, '.'));
                    }));
                    if ($extra) {
                        yield new Hit("{$mapping->statement} maps " . Base::names($extra) . ' to PHP', [], null,
                            Confidence::HIGH, $mapping->location);
                    }
                } elseif ($mapping->filesPattern === null) {
                    yield new Hit("{$mapping->statement} executes every file in the directory as PHP", [], null,
                        Confidence::HIGH, $mapping->location);
                } elseif (preg_match(self::NON_PHP_PATTERN, $mapping->filesPattern)) {
                    yield new Hit(
                        "{$mapping->statement} inside <Files {$mapping->filesPattern}> covers non-PHP files",
                        [],
                        null,
                        Confidence::MEDIUM,
                        $mapping->location
                    );
                }
            }
        });
    }
}

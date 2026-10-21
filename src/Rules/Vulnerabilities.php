<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\CveData;
use PhpIniAudit\Directives;
use PhpIniAudit\OverlayKind;
use PhpIniAudit\Setting;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;
use PhpIniAudit\Versions;

/**
 * Known PHP vulnerabilities whose exploitability depends on the configuration, matched to the PHP version.
 * Fixed-in releases come from php.net/ChangeLog-7.php and ChangeLog-8.php; support dates from
 * php.net/supported-versions.php and php.net/eol.php.
 */
final class Vulnerabilities
{
    /** Branch => [end of security support, last release when already end-of-life]. */
    public const SUPPORT = [
        '5.6' => ['2018-12-31', '5.6.40'],
        '7.0' => ['2019-01-10', '7.0.33'],
        '7.1' => ['2019-12-01', '7.1.33'],
        '7.2' => ['2020-11-30', '7.2.34'],
        '7.3' => ['2021-12-06', '7.3.33'],
        '7.4' => ['2022-11-28', '7.4.33'],
        '8.0' => ['2023-11-26', '8.0.30'],
        '8.1' => ['2025-12-31', '8.1.34'],
        '8.2' => ['2026-12-31', null],
        '8.3' => ['2027-12-31', null],
        '8.4' => ['2028-12-31', null],
        '8.5' => ['2029-12-31', null],
    ];
    public const EOL_WARNING_DAYS = 180;

    public const MIB = 1048576;
    public const SMALL_POST_LIMIT = 32 * self::MIB;

    private const HTTP_WRAPPER = "PHP's http:// stream wrapper";
    private const FPM_SAPIS = ['fpm', 'unknown'];
    private const CGI_SAPIS = ['cgi', 'unknown'];
    private const PHP2SHELL_FIXED = ['8.2.35', '8.3.36', '8.4.27', '8.5.12'];

    /** @var list<Advisory>|null */
    private static ?array $advisories = null;

    /** @return list<array{list<int>, int}> [branch, patch] pairs, one per branch in first-seen order */
    public static function fixesByBranch(array $fixed): array
    {
        $result = [];
        foreach ($fixed as $text) {
            [$major, $minor, $patch] = Versions::parseVersion($text);
            $result["$major.$minor"] = [[$major, $minor], $patch];
        }
        return array_values($result);
    }

    /** @param list<array{list<int>, int}> $fixes */
    public static function patchFor(array $fixes, array $branch): ?int
    {
        foreach ($fixes as [$fixBranch, $patch]) {
            if ($fixBranch === $branch) {
                return $patch;
            }
        }
        return null;
    }

    private static function fpm(Context $ctx): bool
    {
        return $ctx->sapi === 'fpm' || (bool) $ctx->pools;
    }

    /** php-cgi is certain for the cgi SAPI, plausible for an unknown SAPI without FPM pools. */
    private static function cgiConfidence(Context $ctx): ?int
    {
        if ($ctx->sapi === 'cgi') {
            return Confidence::HIGH;
        }
        if ($ctx->sapi === 'unknown' && !$ctx->pools) {
            return $ctx->platform === 'windows' ? Confidence::MEDIUM : Confidence::LOW;
        }
        return null;
    }

    public static function windowsCgi(Context $ctx): ?array
    {
        $confidence = self::cgiConfidence($ctx);
        if ($ctx->platform === 'windows' && $confidence !== null) {
            return ['PHP runs on Windows and may be served through php-cgi', [], $confidence];
        }
        return null;
    }

    public static function forceRedirectCgi(Context $ctx): ?array
    {
        $setting = $ctx->get('cgi.force_redirect');
        $confidence = self::cgiConfidence($ctx);
        if ($confidence !== null && $setting->asBool()) {
            return ['php-cgi relies on cgi.force_redirect', [$setting], $confidence];
        }
        return null;
    }

    public static function windowsProcOpen(Context $ctx): ?array
    {
        if ($ctx->platform === 'windows' && !isset(Execution::disabledFunctions($ctx)['proc_open'])) {
            return ['proc_open() is callable on Windows', [$ctx->get('disable_functions')]];
        }
        return null;
    }

    public static function fpmAny(Context $ctx): ?array
    {
        return self::fpm($ctx) ? ['PHP-FPM is in use', []] : null;
    }

    public static function fpmMultiPool(Context $ctx): ?array
    {
        if (self::fpm($ctx) && count($ctx->pools) > 1) {
            return [count($ctx->pools) . ' FPM pools share one OPcache', []];
        }
        return null;
    }

    public static function poolCatchOutput(Context $ctx): ?array
    {
        $directive = $ctx->pool->settings['catch_workers_output'] ?? null;
        if ($directive !== null && $directive->value !== ''
            && !in_array(strtolower($directive->value), ['no', '0', 'off', 'false'], true)) {
            return ['catch_workers_output is enabled', [$directive]];
        }
        return null;
    }

    public static function poolAllowedClients(Context $ctx): ?array
    {
        $listen = $ctx->pool->settings['listen'] ?? null;
        $allowed = $ctx->pool->settings['listen.allowed_clients'] ?? null;
        if ($listen !== null && !Util::startsWith($listen->value, '/') && $allowed !== null
            && trim($allowed->value) !== '') {
            return ["TCP listener restricted only by listen.allowed_clients = {$allowed->value}", [$allowed, $listen]];
        }
        return null;
    }

    public static function poolStatusPage(Context $ctx): ?array
    {
        $directive = $ctx->pool->settings['pm.status_path'] ?? null;
        if ($directive !== null && trim($directive->value) !== '') {
            return ["pm.status_path = {$directive->value}", [$directive]];
        }
        return null;
    }

    public static function imapLoaded(Context $ctx): ?array
    {
        $directive = Extensions::loadedExtension($ctx, 'imap');
        return $directive !== null ? ['the imap extension is loaded', [$directive]] : null;
    }

    public static function urlFopen(Context $ctx): ?array
    {
        $setting = $ctx->get('allow_url_fopen');
        return $setting->asBool() ? ['allow_url_fopen lets file functions fetch http:// URLs', [$setting]] : null;
    }

    public static function postReading(Context $ctx): ?array
    {
        $setting = $ctx->get('enable_post_data_reading');
        if ($ctx->isWeb() && $setting->asBool()) {
            return ['PHP parses multipart request bodies', [$setting]];
        }
        return null;
    }

    public static function uploads(Context $ctx): ?array
    {
        $setting = $ctx->get('file_uploads');
        if ($ctx->isWeb() && $setting->asBool()) {
            return ['file_uploads is On', [$setting]];
        }
        return null;
    }

    public static function uploadProgress(Context $ctx): ?array
    {
        $setting = $ctx->get('session.upload_progress.enabled');
        if ($ctx->isWeb() && $setting->asBool()) {
            return ['session.upload_progress.enabled is On', [$setting]];
        }
        return null;
    }

    public static function oomPath(Context $ctx): ?array
    {
        $memory = $ctx->get('memory_limit');
        $size = $memory->asBytes();
        if ($size !== null && $size < 0) {
            $reason = "memory_limit = -1 removes PHP's own limit, but allocation failures still reach the "
                . 'vulnerable path';
            $confidence = Confidence::MEDIUM;
        } else {
            $reason = "{$memory->describe()} lets a request run into the out-of-memory path";
            $confidence = Confidence::HIGH;
        }
        $evidence = [$memory];
        $post = $ctx->get('post_max_size');
        $postSize = $post->asBytes();
        if ($postSize !== null && ($postSize <= 0 || $postSize > self::SMALL_POST_LIMIT)) {
            $reason .= "; {$post->describe()} accepts large request bodies";
            $evidence[] = $post;
        }
        return [$reason, $evidence, $confidence];
    }

    /**
     * The value in force while the request body is parsed, and the .user.ini override that comes too late.
     * @return array{Setting, ?Setting}
     */
    private static function beforeRequestParsing(Context $ctx, string $name): array
    {
        $setting = $ctx->get($name);
        if ($ctx->overlayKind !== OverlayKind::USER_INI || !$ctx->config->isOverlay($setting->directive)) {
            return [$setting, null];
        }
        if ($setting->overridden) {
            $previous = $setting->overridden[count($setting->overridden) - 1];
            return [new Setting($name, $previous->value, $previous, array_slice($setting->overridden, 0, -1)),
                $setting];
        }
        return [new Setting($name, Directives::default($name)), $setting];
    }

    public static function staleState(Context $ctx): ?array
    {
        [$progress, $late] = self::beforeRequestParsing($ctx, 'session.upload_progress.enabled');
        $paths = [];
        $evidence = [];
        if ($progress->asBool()) {
            if ($late !== null) {
                $paths[] = "session upload progress stays On because {$late->describe()} in .user.ini applies "
                    . 'after request parsing';
                $evidence[] = $late;
            } else {
                $paths[] = 'session.upload_progress.enabled is On';
                $evidence[] = $progress;
            }
        }
        $backtraces = $ctx->get('fatal_error_backtraces');
        if ($ctx->phpVersion !== null && Util::compare($ctx->phpVersion, [8, 5]) >= 0 && $backtraces->asBool()) {
            $paths[] = 'fatal_error_backtraces is On';
            $evidence[] = $backtraces;
        }
        if ($paths) {
            return [implode('; ', $paths), $evidence];
        }
        return ['the confirmed paths are closed, but other variants remain', [$late ?? $progress],
            Confidence::MEDIUM];
    }

    public static function prefixedSessionCookie(Context $ctx): ?array
    {
        $setting = $ctx->get('session.name');
        if (Util::startsWith($setting->text(), '__Host-') || Util::startsWith($setting->text(), '__Secure-')) {
            return ["session.name = {$setting->text()} relies on the cookie prefix", [$setting]];
        }
        return null;
    }

    private static function advisory(string $cve, string $title, int $severity, array $fixed, string $condition,
        string $description, string $mitigation, ?string $cwe, string $scope = 'config', ?array $sapis = null): Advisory
    {
        $advisory = new Advisory($cve, $title, $severity, $fixed, [self::class, $condition], $description,
            $mitigation);
        $advisory->cwe = $cwe;
        $advisory->scope = $scope;
        $advisory->sapis = $sapis;
        return $advisory;
    }

    /** @return list<Advisory> */
    public static function advisories(): array
    {
        if (self::$advisories !== null) {
            return self::$advisories;
        }
        $http = self::HTTP_WRAPPER;
        return self::$advisories = [
            self::advisory('CVE-2026-109618', 'Remote code execution after an out-of-memory error', Severity::CRITICAL,
                self::PHP2SHELL_FIXED, 'oomPath',
                'When an allocation fails, PHP aborts the request and leaves request memory in an invalid state that '
                . 'shutdown code still uses, so a crafted request can corrupt memory and run code (exploited in the '
                . 'wild). Configuration only reduces exposure.',
                'Upgrade. Until then set memory_limit = -1 with php_admin_value so applications cannot lower it, keep '
                . 'post_max_size at 8M (32M with uploads), and bound memory with a container or cgroup limit rather '
                . 'than RLIMIT_AS/RLIMIT_DATA.', 'CWE-416', 'config', Base::WEB_SAPIS),
            self::advisory('CVE-2026-109619', 'Remote code execution through stale request state', Severity::CRITICAL,
                self::PHP2SHELL_FIXED, 'staleState',
                'Request-owned state survives a fatal error into the next request on the same worker and is used '
                . 'before initialisation. Confirmed paths are session upload progress and, on PHP 8.5, fatal error '
                . 'backtraces; other variants remain.',
                'Upgrade. Until then set session.upload_progress.enabled = 0 in php.ini or the FPM pool (not '
                . '.user.ini or ini_set()), on PHP 8.5 set fatal_error_backtraces = 0, restart every worker, and '
                . 'remove deprecated settings from .user.ini/.htaccess.', 'CWE-416', 'config', Base::WEB_SAPIS),
            self::advisory('CVE-2024-4577', 'php-cgi argument injection on Windows', Severity::CRITICAL,
                ['8.1.29', '8.2.20', '8.3.8'], 'windowsCgi',
                "Windows 'Best-Fit' character conversion lets a soft hyphen in the query string become a php-cgi "
                . 'command-line option, giving remote code execution (exploited in the wild, e.g. default XAMPP).',
                'Upgrade; until then do not expose php-cgi (use PHP-FPM or mod_php).', 'CWE-78', 'config',
                self::CGI_SAPIS),
            self::advisory('CVE-2024-8926', 'Bypass of the CVE-2024-4577 fix', Severity::CRITICAL,
                ['8.1.30', '8.2.24', '8.3.12'], 'windowsCgi',
                'Certain Windows code pages still allow php-cgi argument injection after the CVE-2024-4577 fix.',
                'Upgrade; do not expose php-cgi on Windows.', 'CWE-88', 'config', self::CGI_SAPIS),
            self::advisory('CVE-2024-8927', 'cgi.force_redirect bypass', Severity::HIGH, ['8.1.30', '8.2.24', '8.3.12'],
                'forceRedirectCgi',
                'An environment variable collision lets requests bypass the cgi.force_redirect protection and invoke '
                . 'php-cgi directly.',
                'Upgrade; do not expose php-cgi directly.', 'CWE-284', 'config', self::CGI_SAPIS),
            self::advisory('CVE-2024-1874', 'Command injection through proc_open() on Windows', Severity::HIGH,
                ['8.1.28', '8.2.18', '8.3.6'], 'windowsProcOpen',
                'Array-form proc_open() commands are not escaped correctly for .bat/.cmd files on Windows.',
                'Upgrade, or add proc_open to disable_functions if unused.', 'CWE-78'),
            self::advisory('CVE-2024-5585', 'Bypass of the CVE-2024-1874 fix', Severity::HIGH,
                ['8.1.29', '8.2.20', '8.3.8'], 'windowsProcOpen',
                'Trailing spaces in the command name bypass the CVE-2024-1874 escaping fix for proc_open() on '
                . 'Windows.',
                'Upgrade, or add proc_open to disable_functions if unused.', 'CWE-78'),
            self::advisory('CVE-2019-11043', 'PHP-FPM env_path_info underflow (remote code execution)',
                Severity::CRITICAL, ['7.1.33', '7.2.24', '7.3.11'], 'fpmAny',
                'With nginx configurations that use fastcgi_split_path_info with a regex that can be broken by a '
                . 'newline, a crafted URL corrupts FPM memory and leads to remote code execution (exploited in the '
                . 'wild).',
                'Upgrade; add try_files $fastcgi_script_name =404 before fastcgi_pass.', 'CWE-787', 'config',
                self::FPM_SAPIS),
            self::advisory('CVE-2021-21703', 'PHP-FPM local privilege escalation to root', Severity::HIGH,
                ['7.3.32', '7.4.25', '8.0.12'], 'fpmAny',
                'A compromised FPM worker can write to shared memory of the root master process and escalate to '
                . 'root.',
                'Upgrade.', 'CWE-787', 'config', self::FPM_SAPIS),
            self::advisory('CVE-2018-10545', 'FPM workers can bypass OPcache access controls', Severity::MEDIUM,
                ['7.0.29', '7.1.16', '7.2.4'], 'fpmMultiPool',
                "Dumpable FPM child processes let one pool read another pool's OPcache data via ptrace.",
                'Upgrade; keep process.dumpable = no.', 'CWE-284', 'config', self::FPM_SAPIS),
            self::advisory('CVE-2024-9026', 'PHP-FPM worker output can alter log entries', Severity::LOW,
                ['8.1.30', '8.2.24', '8.3.12'], 'poolCatchOutput',
                'With catch_workers_output, a worker can emit messages that strip characters from log lines, '
                . 'hiding or forging log entries.',
                'Upgrade, or disable catch_workers_output.', 'CWE-117', 'pool'),
            self::advisory('CVE-2026-91768', 'IPv6 bypass of listen.allowed_clients', Severity::HIGH,
                ['8.2.34', '8.3.35', '8.4.26', '8.5.11'], 'poolAllowedClients',
                'listen.allowed_clients compares IPv6 addresses partially, so clients outside the list can reach the '
                . 'unauthenticated FastCGI port.',
                'Upgrade; also firewall the FastCGI port or use a Unix socket.', 'CWE-284', 'pool'),
            self::advisory('CVE-2026-6735', 'XSS in the PHP-FPM status page', Severity::MEDIUM,
                ['8.2.31', '8.3.31', '8.4.21', '8.5.6'], 'poolStatusPage',
                'The FPM status endpoint reflects request data without escaping in its HTML output.',
                'Upgrade, or remove pm.status_path / restrict it to administrators.', 'CWE-79', 'pool'),
            self::advisory('CVE-2018-19518', 'imap_open() runs shell commands', Severity::HIGH,
                ['7.0.33', '7.1.25', '7.2.13'], 'imapLoaded',
                'Before the fix, rsh/ssh mailbox names in imap_open() could inject commands; there was no '
                . 'imap.enable_insecure_rsh switch.',
                'Upgrade and keep imap.enable_insecure_rsh = Off.', 'CWE-78'),
            self::advisory('CVE-2025-1861', 'HTTP wrapper truncates redirect locations', Severity::MEDIUM,
                ['8.1.32', '8.2.28', '8.3.19', '8.4.5'], 'urlFopen',
                "$http truncates Location headers to 1024 bytes, so redirects can lead somewhere else.",
                'Upgrade, or set allow_url_fopen = Off.', 'CWE-131'),
            self::advisory('CVE-2025-1736', 'HTTP wrapper header check may omit headers', Severity::MEDIUM,
                ['8.1.32', '8.2.28', '8.3.19', '8.4.5'], 'urlFopen',
                "$http may miss user-supplied Authorization headers and send unintended headers.",
                'Upgrade, or set allow_url_fopen = Off.', 'CWE-20'),
            self::advisory('CVE-2025-1734', 'HTTP wrapper accepts headers without a colon', Severity::LOW,
                ['8.1.32', '8.2.28', '8.3.19', '8.4.5'], 'urlFopen',
                "$http accepts malformed response headers, enabling response confusion.",
                'Upgrade, or set allow_url_fopen = Off.', 'CWE-436'),
            self::advisory('CVE-2025-1217', 'HTTP wrapper mishandles folded headers', Severity::LOW,
                ['8.1.32', '8.2.28', '8.3.19', '8.4.5'], 'urlFopen',
                "$http does not handle folded headers, so response headers can be misinterpreted.",
                'Upgrade, or set allow_url_fopen = Off.', 'CWE-436'),
            self::advisory('CVE-2025-1219', 'libxml uses the wrong content type after redirects', Severity::LOW,
                ['8.1.32', '8.2.28', '8.3.19', '8.4.5'], 'urlFopen',
                'Remote documents loaded by DOM/SimpleXML through redirects are parsed with the wrong charset.',
                'Upgrade, or set allow_url_fopen = Off.', 'CWE-436'),
            self::advisory('CVE-2024-11234', 'CRLF injection through stream proxy configuration', Severity::MEDIUM,
                ['8.1.31', '8.2.26', '8.3.14'], 'urlFopen',
                "$http with a proxy configured allows CRLF injection in the request URI.",
                'Upgrade, or set allow_url_fopen = Off.', 'CWE-93'),
            self::advisory('CVE-2026-91766', 'HTTP wrapper leaks credentials across origins on redirect',
                Severity::HIGH, ['8.2.34', '8.3.35', '8.4.26', '8.5.11'], 'urlFopen',
                "$http forwards credentials to a different origin when following redirects.",
                'Upgrade, or set allow_url_fopen = Off.', 'CWE-200'),
            self::advisory('CVE-2026-93682', 'HTTP wrapper out-of-bounds read on empty redirect', Severity::MEDIUM,
                ['8.2.34', '8.3.35', '8.4.26', '8.5.11'], 'urlFopen',
                "A redirect with an empty Location header makes $http read out of bounds.",
                'Upgrade, or set allow_url_fopen = Off.', 'CWE-125'),
            self::advisory('CVE-2023-0662', 'Denial of service through multipart request bodies', Severity::MEDIUM,
                ['8.0.28', '8.1.16', '8.2.3'], 'postReading',
                'Requests with many multipart parts consume excessive CPU; the fix introduced '
                . 'max_multipart_body_parts.',
                'Upgrade and keep max_input_vars/max_file_uploads modest.', 'CWE-400', 'config', Base::WEB_SAPIS),
            self::advisory('CVE-2024-8925', 'Erroneous parsing of multipart form data', Severity::MEDIUM,
                ['8.1.30', '8.2.24', '8.3.12'], 'postReading',
                'Malformed multipart boundaries are parsed inconsistently with upstream proxies and WAFs, letting '
                . 'attackers smuggle form fields past filtering.',
                'Upgrade.', 'CWE-436', 'config', Base::WEB_SAPIS),
            self::advisory('CVE-2019-11048', 'Upload temp files left behind by long names', Severity::MEDIUM,
                ['7.2.31', '7.3.18', '7.4.6'], 'uploads',
                'Long file or variable names in multipart requests exhaust memory and leave temporary upload files '
                . 'on disk.',
                'Upgrade.', 'CWE-190', 'config', Base::WEB_SAPIS),
            self::advisory('CVE-2020-7062', 'Crash in session upload progress', Severity::MEDIUM,
                ['7.2.28', '7.3.15', '7.4.3'], 'uploadProgress',
                'A crafted upload with session upload progress enabled dereferences a NULL pointer and crashes the '
                . 'worker.',
                'Upgrade, or set session.upload_progress.enabled = Off.', 'CWE-476', 'config', Base::WEB_SAPIS),
            self::advisory('CVE-2024-2756', '__Host-/__Secure- cookie prefix bypass', Severity::MEDIUM,
                ['8.1.28', '8.2.18', '8.3.6'], 'prefixedSessionCookie',
                'Cookie name mangling lets a non-secure origin set cookies that PHP reads as __Host-/__Secure- '
                . 'cookies (incomplete fix of CVE-2022-31629).',
                'Upgrade.', 'CWE-565', 'config', Base::WEB_SAPIS),
            self::advisory('CVE-2022-31629', '__Host- cookie names can be spoofed', Severity::MEDIUM,
                ['7.4.32', '8.0.24', '8.1.11'], 'prefixedSessionCookie',
                'HTTP variable name mangling lets an attacker set cookies that PHP treats as __Host- prefixed.',
                'Upgrade.', 'CWE-565', 'config', Base::WEB_SAPIS),
            self::advisory('CVE-2020-7070', 'Encoded cookie names allow __Host- spoofing', Severity::MEDIUM,
                ['7.2.34', '7.3.23', '7.4.11'], 'prefixedSessionCookie',
                'PHP URL-decodes cookie names, so a crafted name is read as a __Host- cookie.',
                'Upgrade.', 'CWE-565', 'config', Base::WEB_SAPIS),
        ];
    }

    public static function advisoryFor(string $cve): ?Advisory
    {
        foreach (self::advisories() as $advisory) {
            if ($advisory->cve === $cve) {
                return $advisory;
            }
        }
        return null;
    }

    private static function registerAdvisory(Advisory $advisory): void
    {
        Registry::rule($advisory->cve, $advisory->title, [
            'severity' => $advisory->severity,
            'scope' => $advisory->scope,
            'sapis' => $advisory->sapis,
            'cwe' => $advisory->cwe,
            'description' => "{$advisory->description} Fixed in PHP " . implode(', ', $advisory->fixed) . '.',
            'recommendation' => $advisory->mitigation,
            'references' => ["https://nvd.nist.gov/vuln/detail/{$advisory->cve}"],
        ], static function (Context $ctx) use ($advisory): iterable {
            $version = $ctx->phpVersion;
            if (!$version || $advisory->status($version) !== 'affected') {
                return;
            }
            $match = $advisory->condition($ctx);
            if ($match === null) {
                return;
            }
            [$reason, $evidence] = $match;
            $confidence = $match[2] ?? Confidence::HIGH;
            $message = 'PHP ' . Versions::formatVersion($version) . ' is affected (fixed in '
                . $advisory->fixedFor($version) . "); $reason";
            if ($ctx->versionBackports) {
                $message .= '; the distribution build may carry a backported fix';
                $confidence = Confidence::LOW;
            }
            yield new Hit($message, $evidence, null, $confidence);
        });
    }

    /** Whether the version is, or may be, older than the fix; false when the version is unknown. */
    public static function exposedTo(string $cve, ?array $version): bool
    {
        if (!$version) {
            return false;
        }
        return in_array(self::advisoryFor($cve)->status($version), ['affected', 'possible'], true);
    }

    /** @return iterable<Hit> */
    public static function endOfLife(Context $ctx, ?\DateTimeImmutable $today = null): iterable
    {
        $version = $ctx->phpVersion;
        if (!$version) {
            return;
        }
        $today = ($today ?? new \DateTimeImmutable('today'))->setTime(0, 0);
        $branch = [$version[0], $version[1]];
        $key = "{$branch[0]}.{$branch[1]}";
        if (!isset(self::SUPPORT[$key])) {
            $known = array_map(static function (string $key): array {
                return array_map('intval', explode('.', $key));
            }, array_keys(self::SUPPORT));
            $oldest = Util::sortBy($known, static function (array $b): array {
                return $b;
            })[0];
            if (Util::compare($branch, $oldest) < 0) {
                yield new Hit('PHP ' . Versions::formatVersion($version) . ' reached end of life long ago', [],
                    Severity::CRITICAL);
            }
            return;
        }
        [$endText, $lastRelease] = self::SUPPORT[$key];
        $end = new \DateTimeImmutable($endText, $today->getTimezone());
        $days = (int) $today->diff($end)->format('%r%a');
        if ($days < 0) {
            $last = $lastRelease !== null && $lastRelease !== '' ? "; last release $lastRelease" : '';
            yield new Hit("PHP {$branch[0]}.{$branch[1]} security support ended on $endText$last");
        } elseif ($days <= self::EOL_WARNING_DAYS) {
            yield new Hit(
                "PHP {$branch[0]}.{$branch[1]} security support ends on $endText ($days days)",
                [],
                Severity::LOW
            );
        }
    }

    /** @return iterable<Hit> */
    public static function versionUnknown(Context $ctx): iterable
    {
        $version = $ctx->phpVersion;
        if ($version && count($version) >= 3) {
            return;
        }
        if ($ctx->pool !== null || $ctx->overlayKind !== null) {
            return;
        }
        $pending = [];
        foreach (self::advisories() as $advisory) {
            if ($advisory->sapis !== null && !in_array($ctx->sapi, $advisory->sapis, true)) {
                continue;
            }
            if ($version && $advisory->status($version) !== 'possible') {
                continue;
            }
            if ($advisory->scope === 'pool') {
                $contexts = [];
                foreach ($ctx->pools as $pool) {
                    $copy = clone $ctx;
                    $copy->pool = $pool;
                    $contexts[] = $copy;
                }
            } else {
                $contexts = [$ctx];
            }
            $exposed = false;
            foreach ($contexts as $context) {
                if ($advisory->condition($context) !== null) {
                    $exposed = true;
                    break;
                }
            }
            if (!$exposed) {
                continue;
            }
            $needed = $version ? $advisory->fixedFor($version) : implode('/', $advisory->fixed);
            $pending[] = "{$advisory->cve} (fixed in $needed)";
        }
        if ($pending) {
            $known = $version ? 'PHP ' . Versions::formatVersion($version) : 'PHP version unknown';
            yield new Hit("$known; this configuration is exposed to " . count($pending) . ' CVE(s) unless patched: '
                . implode(', ', $pending), [], null, Confidence::MEDIUM);
        }
    }

    /** @return array{int, int} */
    private static function cveKey(string $cve): array
    {
        [, $year, $number] = explode('-', $cve);
        return [(int) $year, (int) $number];
    }

    /** @return iterable<Hit> */
    public static function disclosedCves(Context $ctx): iterable
    {
        $version = $ctx->phpVersion;
        if (!$version || count($version) < 3) {
            return;
        }
        $branch = [$version[0], $version[1]];
        $affected = [];
        $latestFix = 0;
        foreach (CveData::DISCLOSED as [$cve, $severity, $fixed]) {
            // Changelogs sometimes omit the CVE on a branch, so only a fix listed for this branch counts.
            $patch = self::patchFor(self::fixesByBranch($fixed), $branch);
            if (self::advisoryFor($cve) !== null || $patch === null || $version[2] >= $patch) {
                continue;
            }
            $affected[] = [$severity, $cve];
            $latestFix = max($latestFix, $patch);
        }
        if (!$affected) {
            return;
        }
        $affected = Util::sortBy($affected, static function (array $item): array {
            return [-$item[0], self::cveKey($item[1])];
        });
        $counts = [];
        foreach ([Severity::CRITICAL, Severity::HIGH, Severity::MEDIUM, Severity::LOW] as $level) {
            $count = count(array_filter($affected, static function (array $item) use ($level): bool {
                return $item[0] === $level;
            }));
            if ($count > 0) {
                $counts[] = "$count " . Severity::name($level);
            }
        }
        $message = 'PHP ' . Versions::formatVersion($version) . ' is affected by ' . count($affected)
            . ' publicly disclosed CVE(s) (' . implode(', ', $counts) . "), all fixed by {$branch[0]}.{$branch[1]}."
            . "$latestFix: " . implode(', ', array_column($affected, 1));
        $confidence = Confidence::HIGH;
        if ($ctx->versionBackports) {
            $message .= '; the distribution build may carry backported fixes';
            $confidence = Confidence::LOW;
        }
        yield new Hit($message, [], $affected[0][0], $confidence);
    }

    public static function register(): void
    {
        foreach (self::advisories() as $advisory) {
            self::registerAdvisory($advisory);
        }

        Registry::rule('VULN-001', 'PHP branch without security support', [
            'severity' => Severity::HIGH,
            'cwe' => 'CWE-1104',
            'description' => 'Branches past their end of life receive no security fixes, so every vulnerability '
                . 'found after that date stays open. A branch nearing its end of life is reported early.',
            'recommendation' => 'Upgrade to a supported PHP branch (see php.net/supported-versions.php).',
            'references' => ['https://www.php.net/supported-versions.php', 'https://www.php.net/eol.php'],
        ], [self::class, 'endOfLife']);

        Registry::rule('VULN-002', 'Known vulnerabilities depend on the exact PHP version', [
            'severity' => Severity::INFO,
            'description' => 'Some known CVEs apply to this configuration, but the exact PHP patch version could not '
                . 'be read from the system (php_version.h, dpkg, apk or Homebrew), so the scanner cannot tell '
                . 'whether the fix is installed.',
            'recommendation' => 'Pass --php-version X.Y.Z (from `php -v` run by you), or scan with --root so package '
                . 'metadata can be read.',
        ], [self::class, 'versionUnknown']);

        Registry::rule('VULN-003', 'Publicly disclosed CVEs affect this PHP version', [
            'severity' => Severity::HIGH,
            'description' => 'PHP releases fix publicly disclosed vulnerabilities that do not depend on a particular '
                . 'setting (parsers, extensions, bundled libraries). The finding lists every CVE fixed in a later '
                . 'release of this branch and takes the severity of the worst one; end-of-life branches are covered '
                . 'by VULN-001. CVEs whose exposure depends on the configuration are reported under their own IDs '
                . 'instead.',
            'recommendation' => 'Upgrade to the latest release of a supported PHP branch.',
            'references' => ['https://www.php.net/ChangeLog-8.php', 'https://github.com/php/php-src/security/advisories'],
        ], [self::class, 'disclosedCves']);
    }
}

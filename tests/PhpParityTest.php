<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Auditor;
use PhpIniAudit\AuditResult;
use PhpIniAudit\Directive;
use PhpIniAudit\Directives;
use PhpIniAudit\Discoverer;
use PhpIniAudit\Discovery;
use PhpIniAudit\FileSystem;
use PhpIniAudit\Finding;
use PhpIniAudit\Options;
use PhpIniAudit\Paste;
use PhpIniAudit\Phpinfo;
use PhpIniAudit\Setting;
use PhpIniAudit\Target;
use PhpIniAudit\Util;
use PhpIniAudit\Values;
use PHPUnit\Framework\TestCase;

/**
 * Differential tests: the scanner's effective configuration must match what real PHP resolves.
 * Runs against every php-cgi in $PHP_CGI (PATH_SEPARATOR-separated) or on PATH; skipped when none is found.
 *
 * @group parity
 */
final class PhpParityTest extends TestCase
{
    // Defaults that depend on how PHP was built rather than on PHP itself.
    public const BUILD_DEPENDENT = [
        'curl.cainfo',
        'extension_dir',
        'include_path',
        'mysqli.default_socket',
        'openssl.cafile',
        'openssl.capath',
        'pdo_mysql.default_socket',
        'sendmail_path',
        // Debian patches the compiled-in default to /var/lib/php/sessions.
        'session.save_path',
    ];
    // The table stores the effective value where PHP's INI entry is NULL.
    public const EFFECTIVE_DEFAULTS = ['error_reporting'];
    // [directive, first version, first version no longer affected or null, PHP's default there].
    // The table models the current stable branches; these are the documented departures from it.
    public const VERSIONED_DEFAULTS = [
        ['assert.exception', [0], [8, 0], '0'],
        ['display_startup_errors', [0], [8, 0], '0'],
        ['date.timezone', [8, 2], null, 'UTC'],
        ['opcache.jit', [8, 0], [8, 4], 'tracing'],
        ['opcache.jit', [8, 4], null, 'disable'],
        ['opcache.jit_buffer_size', [8, 4], null, '64M'],
        ['opcache.jit_hot_loop', [8, 4], null, '61'],
        ['register_argc_argv', [8, 5], null, '0'],
        ['session.cookie_httponly', [8, 6], null, '1'],
        ['session.cookie_samesite', [8, 6], null, 'Lax'],
        ['session.use_strict_mode', [8, 6], null, '1'],
    ];
    private const PHP_INI_PERDIR = 2;

    // Each case is a php.ini and an optional scan dir; every directive the scanner resolves is compared.
    private const LAYERING_CASES = [
        'quoting' => [
            'php.ini' => "default_charset = \"ISO-8859-1\"\n"
                . "arg_separator.output = '&amp;'\n"
                . "error_prepend_string = \"<b>quoted ; not a comment</b>\"\n"
                . "error_append_string = \"say \\\"hi\\\"\"\n"
                . "user_agent = \"a\" b \"c\"\n"
                . "date.timezone = Europe/Warsaw ; trailing comment\n"
                . "precision =   12   \n"
                . "docref_root = \"\"\n",
        ],
        'booleans' => [
            'php.ini' => "display_errors = On\n"
                . "log_errors = yes\n"
                . "html_errors = true\n"
                . "expose_php = Off\n"
                . "allow_url_fopen = no\n"
                . "file_uploads = false\n"
                . "enable_dl = None\n"
                . "short_open_tag = 0\n"
                . "implicit_flush = 1\n"
                . "auto_globals_jit = \"Off\"\n"
                . "ignore_user_abort = TRUE\n"
                . "session.use_strict_mode = on\n",
        ],
        'sizes_and_lists' => [
            'php.ini' => "memory_limit = 256M\n"
                . "post_max_size = 1G\n"
                . "upload_max_filesize = 512k\n"
                . "disable_functions = exec, system,shell_exec\n"
                . "variables_order = \"GPCS\"\n",
        ],
        'error_reporting' => [
            'php.ini' => "error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT\n",
        ],
        'error_reporting_numeric' => [
            'php.ini' => "error_reporting = 22519\n",
        ],
        'error_reporting_grouping' => [
            'php.ini' => "error_reporting = (E_ERROR | E_WARNING) & ~E_NOTICE\n",
        ],
        'multiline_quoted' => [
            'php.ini' => "error_append_string = \"line one\nline two\"\nprecision = 10\n",
        ],
        'duplicates_last_wins' => [
            'php.ini' => "memory_limit = 64M\n[Session]\nmemory_limit = 96M\n[PHP]\nmemory_limit = 128M\n",
        ],
        'scan_dir_order' => [
            'php.ini' => "memory_limit = 64M\ndisplay_errors = On\nprecision = 10\n",
            'conf.d/20-b.ini' => "memory_limit = 96M\nprecision = 11\n",
            'conf.d/10-a.ini' => "memory_limit = 80M\ndisplay_errors = Off\n",
            'conf.d/99-z.ini' => "precision = 13\n",
            'conf.d/notes.txt' => "precision = 99\n",
        ],
        'scan_dir_only' => [
            'conf.d/00-base.ini' => "memory_limit = 200M\nexpose_php = Off\n",
        ],
        'unknown_and_removed' => [
            // Fatal-on-startup removed directives such as safe_mode are left out: PHP refuses to run with them.
            'php.ini' => "session.hash_function = 1\nmy_custom.setting = 5\nmemory_limit = 64M\n",
        ],
    ];

    /** @var list<string> */
    private array $binaries = [];
    /** @var list<string> */
    private array $temps = [];

    protected function setUp(): void
    {
        $this->binaries = PhpOracle::cgiBinaries();
        if (!$this->binaries) {
            $this->markTestSkipped('php-cgi not found; set PHP_CGI to run parity tests');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->temps as $temp) {
            Helpers::removeTree($temp);
        }
        $this->temps = [];
    }

    private function tempDir(): string
    {
        $dir = Helpers::tempDir();
        $this->temps[] = $dir;
        return $dir;
    }

    /** @param list<int> $version */
    public static function versionedDefault(string $name, array $version): ?string
    {
        foreach (self::VERSIONED_DEFAULTS as [$directive, $since, $until, $value]) {
            if ($directive === $name && Util::compare($since, $version) <= 0
                && ($until === null || Util::compare($version, $until) < 0)) {
                return $value;
            }
        }
        return null;
    }

    /** @return list<Target> */
    private static function scannerTargets(?string $ini = null, ?string $scanDir = null, ?string $userIni = null,
                                           string $sapi = 'cgi'): array
    {
        $fs = new FileSystem();
        $discoverer = new Discoverer($fs);
        $discovery = new Discovery();
        if ($ini !== null || $scanDir !== null) {
            $directory = $ini !== null ? dirname($ini) : $scanDir;
            $discovery->installations[] = $discoverer->build($ini, $directory, $scanDir !== null ? [$scanDir] : []);
        }
        if ($userIni !== null) {
            $discovery->userInis[] = $userIni;
        }
        return (new Auditor($fs, Helpers::options(['sapi' => $sapi, 'pathChecks' => false])))->buildTargets($discovery);
    }

    /**
     * @param string|false|null $value
     * @return string|int|false|null
     */
    private static function comparable(string $name, $value)
    {
        if ($name === 'error_reporting') {
            return Values::evalErrorReporting($value);
        }
        return $value;
    }

    /** @param array<string, string> $files */
    private static function writeFiles(string $root, array $files): void
    {
        foreach ($files as $name => $content) {
            Helpers::writeFile("$root/$name", $content);
        }
    }

    /** @param mixed $value */
    private static function repr($value): string
    {
        return is_string($value) ? Util::repr($value) : var_export($value, true);
    }

    // DirectiveTableParityTest

    public function testDefaultsAndPerDirModes(): void
    {
        foreach ($this->binaries as $binary) {
            $report = PhpOracle::run($binary, null, null, [], true);
            $version = PhpOracle::versionTuple($report['version']);
            $problems = [];
            $known = Directives::KNOWN;
            ksort($known, SORT_STRING);
            foreach ($known as $name => [$default, $mode]) {
                $name = (string) $name;
                $entry = $report['all'][$name] ?? null;
                if ($entry === null) {
                    continue;
                }
                $phpDefault = $entry['global_value'];
                $phpPerDir = ($entry['access'] & self::PHP_INI_PERDIR) !== 0;
                if ($phpPerDir !== (($mode & Directives::PERDIR) !== 0)) {
                    $problems[] = "$name: per-dir changeable is " . ($phpPerDir ? 'True' : 'False') . ' in PHP';
                }
                if (in_array($name, self::BUILD_DEPENDENT, true) || in_array($name, self::EFFECTIVE_DEFAULTS, true)) {
                    continue;
                }
                if ($phpDefault === $default || ($phpDefault === null && $default === '')) {
                    continue;
                }
                if (self::versionedDefault($name, $version) === $phpDefault) {
                    continue;
                }
                $problems[] = "$name: table " . self::repr($default)
                    . ", PHP {$report['version']} " . self::repr($phpDefault);
            }
            $this->assertSame([], $problems, $binary);
        }
    }

    public function testEffectiveErrorReportingDefault(): void
    {
        $compared = 0;
        foreach ($this->binaries as $binary) {
            $report = PhpOracle::run($binary, null, null, ['error_reporting']);
            if (Util::compare(PhpOracle::versionTuple($report['version']), [8, 0]) < 0) {
                continue;
            }
            $compared++;
            $expected = Values::evalErrorReporting(Directives::default('error_reporting'));
            $this->assertContains($report['values']['error_reporting'], [null, '', (string) $expected], $binary);
        }
        if ($compared === 0) {
            $this->markTestSkipped('needs php-cgi 8.0 or later');
        }
    }

    // LayeringParityTest

    /** @param array<string, string> $files */
    private function assertSameView(string $binary, string $case, array $files): void
    {
        $tmp = $this->tempDir();
        self::writeFiles($tmp, $files);
        $ini = array_key_exists('php.ini', $files) ? "$tmp/php.ini" : null;
        $scanDir = null;
        foreach (array_keys($files) as $name) {
            if (Util::startsWith((string) $name, 'conf.d/')) {
                $scanDir = "$tmp/conf.d";
            }
        }
        $config = self::scannerTargets($ini, $scanDir)[0]->config;
        $settings = array_values(array_filter($config->explicit(), static function (Setting $s): bool {
            return !$s->unresolved();
        }));
        $this->assertNotEmpty($settings, "$binary $case");
        $report = PhpOracle::run($binary, $ini ?? "$tmp/missing.ini", $scanDir, array_map(static function (Setting $s) {
            return $s->name;
        }, $settings));
        $mismatches = [];
        foreach ($settings as $setting) {
            $phpValue = $report['values'][$setting->name];
            // Unknown to this build: removed directive, custom name or extension not loaded.
            if ($phpValue === false) {
                continue;
            }
            if (self::comparable($setting->name, $setting->value) !== self::comparable($setting->name, $phpValue)) {
                $mismatches[$setting->name] = [$setting->value, $phpValue];
            }
        }
        $this->assertSame([], $mismatches, "$binary $case: scanner value vs PHP value");
    }

    public function testLayeringCases(): void
    {
        foreach ($this->binaries as $binary) {
            foreach (self::LAYERING_CASES as $case => $files) {
                $this->assertSameView($binary, $case, $files);
            }
        }
    }

    // OverlayParityTest

    public function testPathSectionAppliesToRequestsBelowIt(): void
    {
        foreach ($this->binaries as $binary) {
            $root = $this->tempDir();
            $docroot = "$root/www";
            $ini = "$root/php.ini";
            file_put_contents($ini, "memory_limit = 64M\nprecision = 10\n"
                . "[PATH=$docroot/legacy]\nmemory_limit = 99M\ndisplay_errors = On\n"
                . "[PATH=$docroot/other]\nprecision = 3\n");
            $legacy = null;
            foreach (self::scannerTargets($ini) as $target) {
                if ($target->overlay !== null && $target->overlay !== '' && strpos($target->overlay, 'legacy') !== false) {
                    $legacy = $target;
                    break;
                }
            }
            $this->assertNotNull($legacy);
            $names = ['memory_limit', 'precision', 'display_errors'];
            $report = PhpOracle::run($binary, $ini, null, $names, false, "$docroot/legacy/app", $docroot);
            foreach ($names as $name) {
                $this->assertSame($report['values'][$name], $legacy->config->get($name)->value, "$binary $name");
            }
        }
    }

    public function testUserIniAppliesOnlyPerDirDirectives(): void
    {
        $requested = [
            'memory_limit' => '33M',
            'precision' => '7',
            'upload_max_filesize' => '64M',
            'session.upload_progress.enabled' => '0',
            'disable_functions' => 'phpinfo',
            'allow_url_fopen' => '0',
            'expose_php' => '0',
            'user_ini.filename' => 'evil.ini',
        ];
        foreach ($this->binaries as $binary) {
            $root = $this->tempDir();
            // open_basedir is per-dir changeable; it must still allow the dump script.
            $overlay = $requested + ['open_basedir' => $root];
            $docroot = "$root/www";
            $app = "$docroot/app";
            mkdir($app, 0777, true);
            $ini = "$root/php.ini";
            file_put_contents($ini, "memory_limit = 64M\ndisable_functions = exec\nallow_url_fopen = On\n");
            $userIni = "$app/.user.ini";
            $lines = '';
            foreach ($overlay as $name => $value) {
                $lines .= "$name = $value\n";
            }
            file_put_contents($userIni, $lines);
            $target = null;
            foreach (self::scannerTargets($ini, null, $userIni) as $candidate) {
                if ($candidate->overlay !== null && $candidate->overlay !== '') {
                    $target = $candidate;
                    break;
                }
            }
            $this->assertNotNull($target);
            $ineffective = array_map(static function (Directive $d): string {
                return $d->name;
            }, $target->config->ineffective);
            $report = PhpOracle::run($binary, $ini, null, array_keys($overlay), false, $app, $docroot);
            foreach ($overlay as $name => $value) {
                $phpValue = $report['values'][$name];
                if ($phpValue === false) {
                    continue;
                }
                $appliedByPhp = $phpValue === $value;
                $this->assertSame($appliedByPhp, !in_array($name, $ineffective, true), "$binary $name");
                $this->assertSame($phpValue, $target->config->get($name)->value, "$binary $name");
            }
        }
    }

    // PhpinfoParityTest

    public function testPhpinfoValuesMatchIniGet(): void
    {
        foreach ($this->binaries as $binary) {
            $dir = $this->tempDir();
            $ini = "$dir/php.ini";
            file_put_contents($ini, "display_errors = On\nallow_url_include = On\nmemory_limit = -1\n"
                . "open_basedir = /srv:$dir\n"
                . "error_reporting = E_ALL & ~E_DEPRECATED\nsession.save_path = \"/var/lib/php & sessions\"\n"
                . "disable_functions = exec,system\n");
            [$html, $expected] = PhpOracle::phpinfo($binary, $ini);
            $info = Phpinfo::parse($html);
            $target = Phpinfo::buildTarget($info, new Options());
            $this->assertSame(PhpOracle::versionTuple($info->fields['PHP Version']), $target->phpVersion, $binary);
            $this->assertSame('cgi', $target->sapi, $binary);
            $this->assertSame([$ini], $target->files, $binary);
            $mismatches = [];
            $common = 0;
            foreach (array_keys($info->settings) as $name) {
                $name = (string) $name;
                if (!array_key_exists($name, $expected)) {
                    continue;
                }
                $common++;
                $actual = $target->config->get($name)->value;
                if (self::comparableDisplayed($name, $actual) !== self::comparableDisplayed($name, $expected[$name])) {
                    $mismatches[$name] = [$actual, $expected[$name]];
                }
            }
            $this->assertSame([], $mismatches, "$binary: phpinfo() value vs ini_get()");
            $this->assertGreaterThan(100, $common, $binary);
        }
    }

    public function testIniDumpScriptMatchesPhpinfo(): void
    {
        $script = (string) file_get_contents(__DIR__ . '/../docs/assets/ini-dump.php');
        foreach ($this->binaries as $binary) {
            $dir = $this->tempDir();
            $ini = "$dir/php.ini";
            file_put_contents($ini, "display_errors = On\nallow_url_include = On\nexpose_php = Off\n"
                . "session.use_strict_mode = 0\n"
                . "memory_limit = -1\nerror_reporting = E_ALL & ~E_DEPRECATED\ndisable_functions = exec,system\n");
            [$html] = PhpOracle::phpinfo($binary, $ini);
            $dump = PhpOracle::output($binary, $ini, $script);
            $this->assertSame('phpinfo', Paste::detect($dump), $binary);
            $expected = self::findingKeys(Paste::audit($html)[1]);
            $this->assertSame($expected, self::findingKeys(Paste::audit($dump)[1]), $binary);
        }
    }

    /** @return list<array{0: string, 1: string|null}> */
    private static function findingKeys(AuditResult $result): array
    {
        $keys = array_map(static function (Finding $f): array {
            return [$f->ruleId, $f->directive];
        }, $result->findings);
        return Util::sortBy($keys, static function (array $key): array {
            return $key;
        });
    }

    /**
     * phpinfo() prints booleans as On/Off where ini_get() returns the raw string.
     *
     * @param string|null $value
     * @return string|int|bool|null
     */
    private static function comparableDisplayed(string $name, ?string $value)
    {
        if ($name === 'error_reporting') {
            return Values::evalErrorReporting($value === null || $value === '' ? '0' : $value);
        }
        if (in_array($value, [null, '', '0', '1', 'On', 'Off'], true)) {
            return Values::toBool($value);
        }
        // phpinfo() trims cell whitespace.
        return trim($value);
    }
}

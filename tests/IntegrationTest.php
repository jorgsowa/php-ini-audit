<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\FileSystem;
use PhpIniAudit\ReadError;
use PHPUnit\Framework\TestCase;

final class IntegrationTest extends TestCase
{
    private const ROOT = __DIR__ . '/..';

    /** @var array<string, mixed> */
    private array $report = [];
    /** @var list<array{0: string, 1: string}> */
    private array $ids = [];

    /** @return array<string, mixed> */
    private static function json(string $text): array
    {
        return json_decode($text, true, 512, JSON_THROW_ON_ERROR);
    }

    /** @return list<string> */
    private static function ruleIds(array $report): array
    {
        return array_values(array_unique(array_column($report['findings'], 'rule_id')));
    }

    private function loadDebian(): void
    {
        [$code, $out] = Helpers::runCli('--root', Helpers::FIXTURES . '/debian', '--format', 'json');
        $this->assertSame(0, $code);
        $this->report = self::json($out);
        $this->ids = array_map(static function (array $f): array {
            return [$f['rule_id'], $f['target']];
        }, $this->report['findings']);
    }

    private static function anyContains(array $haystacks, string $needle): bool
    {
        foreach ($haystacks as $text) {
            if (strpos($text, $needle) !== false) {
                return true;
            }
        }
        return false;
    }

    // DebianFixtureTest

    public function testDebianTargets(): void
    {
        $this->loadDebian();
        $names = array_column($this->report['targets'], 'name');
        $this->assertContains('/etc/php/8.2/cli/php.ini', $names);
        $this->assertContains('/etc/php/8.2/fpm/php.ini', $names);
        $this->assertTrue(self::anyContains($names, 'pool [www]'));
        $this->assertTrue(self::anyContains($names, '[PATH=/var/www/legacy]'));
        $fpm = null;
        foreach ($this->report['targets'] as $target) {
            if ($target['name'] === '/etc/php/8.2/fpm/php.ini') {
                $fpm = $target;
                break;
            }
        }
        $this->assertNotNull($fpm);
        $this->assertSame('8.2.7', $fpm['php_version']);
        $this->assertSame('fpm', $fpm['sapi']);
    }

    public function testDebianPoolFindingsBelongToPool(): void
    {
        $this->loadDebian();
        $poolRules = [];
        foreach ($this->ids as [$rid, $target]) {
            if (strpos($target, 'pool [www]') !== false) {
                $poolRules[] = $rid;
            }
        }
        foreach (['FPM-001', 'FPM-002', 'FPM-003', 'FPM-004', 'FPM-007', 'FS-002', 'ERR-001'] as $rid) {
            $this->assertContains($rid, $poolRules);
        }
        $this->assertNotContains('SESS-001', $poolRules);
    }

    public function testDebianScanDirOverrideWins(): void
    {
        $this->loadDebian();
        $fpmRules = [];
        foreach ($this->ids as [$rid, $target]) {
            if ($target === '/etc/php/8.2/fpm/php.ini') {
                $fpmRules[] = $rid;
            }
        }
        $this->assertNotContains('ERR-001', $fpmRules);
        $this->assertContains('EXT-001', $fpmRules);
    }

    public function testDebianSummaryCountsEverySeverity(): void
    {
        $this->loadDebian();
        $severities = array_keys($this->report['summary']['by_severity']);
        sort($severities);
        $this->assertSame(['critical', 'high', 'info', 'low', 'medium'], $severities);
    }

    // DockerFixtureTest

    public function testDockerMissingPhpIni(): void
    {
        [, $out] = Helpers::runCli('--root', Helpers::FIXTURES . '/docker', '--format', 'json');
        $ids = self::ruleIds(self::json($out));
        $this->assertContains('CFG-006', $ids);
        $this->assertContains('EXEC-011', $ids);
        $this->assertContains('FPM-001', $ids);
    }

    // WebrootFixtureTest

    public function testWebrootOverlays(): void
    {
        [, $out] = Helpers::runCli(Helpers::FIXTURES . '/webroot', '--format', 'json');
        $ids = self::ruleIds(self::json($out));
        foreach (['HTA-001', 'CFG-005', 'EXEC-004'] as $rid) {
            $this->assertContains($rid, $ids);
        }
        $this->assertNotContains('FS-001', $ids);
    }

    // CliTest

    public function testFailOn(): void
    {
        [$code] = Helpers::runCli('--root', Helpers::FIXTURES . '/debian', '--fail-on', 'critical');
        $this->assertSame(1, $code);
        [$code] = Helpers::runCli(Helpers::FIXTURES . '/hardened/php.ini', '--fail-on', 'low');
        $this->assertSame(0, $code);
    }

    public function testSarif(): void
    {
        [, $out] = Helpers::runCli('--root', Helpers::FIXTURES . '/debian', '--format', 'sarif');
        $sarif = self::json($out);
        $this->assertSame('2.1.0', $sarif['version']);
        $this->assertNotEmpty($sarif['runs'][0]['results']);
    }

    public function testRulesCommand(): void
    {
        [$code, $out] = Helpers::runCli('rules', '--format', 'json');
        $this->assertSame(0, $code);
        $this->assertGreaterThan(50, count(self::json($out)));
        [$code] = Helpers::runCli('rules', 'NOPE-001');
        $this->assertSame(2, $code);
    }

    public function testUnknownSelector(): void
    {
        [$code] = Helpers::runCli(Helpers::FIXTURES . '/hardened', '--only', 'BOGUS');
        $this->assertSame(2, $code);
    }

    public function testDiscover(): void
    {
        [, $out] = Helpers::runCli('discover', '--root', Helpers::FIXTURES . '/debian');
        $this->assertStringContainsString('/etc/php/8.2/fpm/pool.d/www.conf', $out);
    }

    public function testTextHidesInfoByDefault(): void
    {
        $debian = Helpers::FIXTURES . '/debian';
        [, $json] = Helpers::runCli('--root', $debian, '--format', 'json');
        $info = self::json($json)['summary']['by_severity']['info'];
        $this->assertGreaterThan(0, $info);
        [, $out] = Helpers::runCli('--root', $debian, '--no-color');
        $this->assertStringNotContainsString('  INFO ', $out);
        $this->assertStringContainsString("$info info finding(s) hidden; show them with --min-severity info", $out);
        $this->assertLessThan(strpos($out, '== '), strpos($out, 'Summary'));
        [, $out] = Helpers::runCli('--root', $debian, '--no-color', '--min-severity', 'info');
        $this->assertStringContainsString('  INFO ', $out);
        $this->assertStringNotContainsString('hidden', $out);
    }

    public function testTextMarksOnlyReducedConfidence(): void
    {
        [, $out] = Helpers::runCli('--root', Helpers::FIXTURES . '/debian', '--no-color');
        $this->assertStringNotContainsString('confidence high', $out);
        $this->assertStringNotContainsString('(high confidence)', $out);
        $this->assertStringContainsString('(low confidence)', $out);
    }

    public function testTextNamesVersionSourceOncePerInstallation(): void
    {
        [, $out] = Helpers::runCli('--root', Helpers::FIXTURES . '/debian', '--no-color', '--min-severity', 'info');
        $this->assertSame(2, substr_count($out, 'from /var/lib/dpkg/status'));
    }

    public function testGroupByRule(): void
    {
        [$code, $out] = Helpers::runCli('--root', Helpers::FIXTURES . '/debian', '--no-color', '--group-by', 'rule');
        $this->assertSame(0, $code);
        $this->assertSame(1, preg_match_all('/^  CRITICAL VULN-003 .*\(2\)$/m', $out));
        $this->assertStringContainsString("           - /etc/php/8.2/cli/php.ini  (low confidence)\n", $out);
        $this->assertStringContainsString("           - /etc/php/8.2/fpm/php.ini  (low confidence)\n", $out);
    }

    public function testSummaryLine(): void
    {
        [$code, $out] = Helpers::runCli('--root', Helpers::FIXTURES . '/debian', '--summary');
        $this->assertSame(0, $code);
        $this->assertMatchesRegularExpression(
            '/^\d+ critical, \d+ high, \d+ medium, \d+ low, \d+ info in 2 configuration\(s\), 2 overlay\(s\), '
            . '5 file\(s\)\n\z/', $out);
        [$code] = Helpers::runCli('--root', Helpers::FIXTURES . '/debian', '--summary', '--format', 'json');
        $this->assertSame(2, $code);
    }

    // ProcessTest: the installed entry point, run as a separate process.

    /** @return array{0: int, 1: string, 2: string} [exit code, stdout, stderr] */
    private function runBinary(string ...$argv): array
    {
        $env = getenv();
        $env['NO_COLOR'] = '1';
        $command = array_merge([PHP_BINARY, self::ROOT . '/bin/php-ini-audit'], $argv);
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
        $this->assertIsResource($process);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($process), $stdout, $stderr];
    }

    public function testProcessExitCodes(): void
    {
        $debian = Helpers::FIXTURES . '/debian';
        $this->assertSame(0, $this->runBinary('--root', $debian)[0]);
        $this->assertSame(1, $this->runBinary('--root', $debian, '--fail-on', 'high')[0]);
        $this->assertSame(2, $this->runBinary('--root', $debian, '--fail-on', 'bogus')[0]);
        $this->assertSame(2, $this->runBinary('--root', Helpers::FIXTURES . '/missing')[0]);
    }

    public function testProcessOutputFileKeepsStdoutClean(): void
    {
        $tmp = Helpers::tempDir();
        try {
            $report = $tmp . '/report.sarif';
            [$code, $stdout, $stderr] = $this->runBinary('--root', Helpers::FIXTURES . '/debian', '--format', 'sarif',
                '-o', $report);
            $this->assertSame(0, $code, $stderr);
            $this->assertSame('', $stdout);
            $this->assertNotEmpty(self::json((string) file_get_contents($report))['runs'][0]['results']);
        } finally {
            Helpers::removeTree($tmp);
        }
    }

    public function testProcessMissingPathIsAUsageError(): void
    {
        [$code, $stdout, $stderr] = $this->runBinary(Helpers::FIXTURES . '/hardened/php.ini',
            Helpers::FIXTURES . '/nope.ini', '--format', 'json');
        $this->assertSame(2, $code);
        $this->assertStringContainsString('cannot read', $stderr);
        $warnings = self::json($stdout)['warnings'];
        $this->assertTrue(self::anyContains($warnings, 'nope.ini'), json_encode($warnings));
    }

    public function testProcessNothingAuditedIsAUsageError(): void
    {
        $missing = Helpers::FIXTURES . '/nope';
        $this->assertSame(2, $this->runBinary($missing)[0]);
        $this->assertSame(2, $this->runBinary($missing, '--fail-on', 'high')[0]);
        $this->assertSame(2, $this->runBinary('--ini', Helpers::FIXTURES . '/nope.ini')[0]);
        $empty = Helpers::tempDir();
        try {
            [$code, , $stderr] = $this->runBinary($empty);
            $this->assertSame(2, $code);
            $this->assertStringContainsString('no PHP configuration audited', $stderr);
        } finally {
            Helpers::removeTree($empty);
        }
    }

    public function testProcessUnwritableOutputIsAUsageError(): void
    {
        [$code, , $stderr] = $this->runBinary(Helpers::FIXTURES . '/hardened/php.ini', '-o',
            Helpers::FIXTURES . '/nope/report.txt');
        $this->assertSame(2, $code);
        $this->assertStringContainsString('cannot write', $stderr);
    }

    public function testProcessTextReportIsPlainWhenPiped(): void
    {
        [, $stdout] = $this->runBinary('--root', Helpers::FIXTURES . '/debian');
        $this->assertStringNotContainsString("\033[", $stdout);
        $this->assertStringContainsString('Summary', $stdout);
    }

    // FilesystemSafetyTest

    private static function skipUnlessPosix(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            self::markTestSkipped('POSIX permissions and symlinks');
        }
    }

    public function testSymlinksCannotEscapeRoot(): void
    {
        self::skipUnlessPosix();
        $outside = Helpers::tempDir();
        $root = Helpers::tempDir();
        try {
            $secret = $outside . '/secret.ini';
            file_put_contents($secret, "x = 1\n");
            mkdir($root . '/etc');
            symlink($secret, $root . '/etc/php.ini');
            $fs = new FileSystem($root);
            $this->assertSame($secret, $fs->resolve('/etc/php.ini'));
            $this->expectException(ReadError::class);
            $fs->readText('/etc/php.ini');
        } finally {
            Helpers::removeTree($outside);
            Helpers::removeTree($root);
        }
    }

    public function testFifoIsNotRead(): void
    {
        self::skipUnlessPosix();
        $root = Helpers::tempDir();
        try {
            $fifo = $root . '/php.ini';
            if (function_exists('posix_mkfifo')) {
                $this->assertTrue(posix_mkfifo($fifo, 0600));
            } else {
                exec('mkfifo ' . escapeshellarg($fifo), $unused, $status);
                $this->assertSame(0, $status);
            }
            $this->expectException(ReadError::class);
            (new FileSystem())->readText($fifo);
        } finally {
            @unlink($root . '/php.ini');
            Helpers::removeTree($root);
        }
    }

    public function testWorldWritableConfigAndPaths(): void
    {
        self::skipUnlessPosix();
        $root = Helpers::tempDir();
        try {
            mkdir($root . '/etc');
            $shared = $root . '/srv/shared';
            mkdir($shared, 0777, true);
            chmod($shared, 0777);
            $ini = $root . '/etc/php.ini';
            file_put_contents($ini, "opcache.file_cache = /srv/shared\nerror_log = /srv/www/public/php.log\n");
            chmod($ini, 0666);
            chmod($root . '/etc', 0755);
            [, $out] = Helpers::runCli('--root', $root, '--ini', '/etc/php.ini', '--path-checks', 'on', '--format', 'json');
            $report = self::json($out);
            $ids = self::ruleIds($report);
            $this->assertContains('FS-011', $ids);
            $this->assertContains('FS-005', $ids);
            $this->assertContains('FS-006', $ids);
            $ww = null;
            foreach ($report['findings'] as $finding) {
                if ($finding['rule_id'] === 'FS-005') {
                    $ww = $finding;
                    break;
                }
            }
            $this->assertStringContainsString('/srv/shared', $ww['message']);
            chmod($shared, 0755);
        } finally {
            Helpers::removeTree($root);
        }
    }
}

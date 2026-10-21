<?php

namespace PhpIniAudit\Tests;

use PHPUnit\Framework\TestCase;

/**
 * End-to-end snapshots of full scans over the fixtures.
 * Regenerate after an intended change with: UPDATE_GOLDEN=1 vendor/bin/phpunit tests/GoldenTest.php
 */
final class GoldenTest extends TestCase
{
    private const GOLDEN = __DIR__ . '/golden';
    // Path checks depend on the checkout's permissions, so snapshots leave them off.
    private const SCENARIOS = [
        'debian' => ['--root', 'debian'],
        'debian-development' => ['--root', 'debian', '--profile', 'development'],
        'debian-old-patch' => ['--root', 'debian', '--php-version', '8.2.0'],
        'docker' => ['--root', 'docker'],
        'hardened' => ['hardened/php.ini'],
        'webroot' => ['webroot'],
        'windows-xampp' => ['windows-xampp/php.ini'],
    ];

    /** @return list<string> */
    private static function cliArgs(string $scenario): array
    {
        $args = [];
        foreach (self::SCENARIOS[$scenario] as $arg) {
            $path = Helpers::FIXTURES . '/' . $arg;
            $args[] = file_exists($path) ? $path : $arg;
        }
        return array_merge($args, ['--path-checks', 'off', '--format', 'json']);
    }

    /** @param mixed $text */
    private static function clean($text): string
    {
        if ($text === null) {
            return '-';
        }
        return str_replace(DIRECTORY_SEPARATOR, '/', str_replace(Helpers::FIXTURES, '<fixtures>', (string) $text));
    }

    private static function snapshot(array $report): string
    {
        $lines = ['[targets]'];
        foreach ($report['targets'] as $target) {
            $version = $target['php_version'] ?? 'unknown';
            if ($target['php_version_source'] !== null && $target['php_version_source'] !== '') {
                $version .= " from {$target['php_version_source']}";
            }
            $flags = $target['defaults_only'] ? ' defaults-only' : '';
            $lines[] = self::clean($target['name']) . "  sapi={$target['sapi']} php=" . self::clean($version) . $flags;
            foreach ($target['files'] as $path) {
                $lines[] = '  file ' . self::clean($path);
            }
        }
        $lines[] = '[warnings]';
        foreach ($report['warnings'] as $warning) {
            $lines[] = self::clean($warning);
        }
        $lines[] = '[findings]';
        foreach ($report['findings'] as $f) {
            $where = $f['line'] ? self::clean($f['file']) . ':' . $f['line'] : self::clean($f['file']);
            if ($f['from_default']) {
                $where = 'default';
            }
            $lines[] = sprintf('%-8s %-6s %-14s ', $f['severity'], $f['confidence'], $f['rule_id'])
                . self::clean($f['directive']) . '=' . self::clean($f['value'])
                . "  at $where  in " . self::clean($f['target']);
        }
        $lines[] = '[summary]';
        $lines[] = self::compactJson($report['summary']['by_severity']);
        return implode("\n", $lines) . "\n";
    }

    /** A flat object of ints as {"a": 1, "b": 2}, the layout the golden files use. */
    private static function compactJson(array $counts): string
    {
        $parts = [];
        foreach ($counts as $key => $value) {
            $parts[] = json_encode((string) $key) . ': ' . json_encode($value);
        }
        return '{' . implode(', ', $parts) . '}';
    }

    /** @return array<string, array{0: string}> */
    public function scenarios(): array
    {
        $cases = [];
        foreach (array_keys(self::SCENARIOS) as $scenario) {
            $cases[$scenario] = [$scenario];
        }
        return $cases;
    }

    /** @dataProvider scenarios */
    public function testScenarios(string $scenario): void
    {
        $update = (string) getenv('UPDATE_GOLDEN') !== '';
        [$code, $out, $err] = Helpers::runCli(...self::cliArgs($scenario));
        $this->assertSame(0, $code, $err);
        $actual = self::snapshot(json_decode($out, true, 512, JSON_THROW_ON_ERROR));
        $path = self::GOLDEN . "/$scenario.txt";
        if ($update) {
            if (!is_dir(self::GOLDEN)) {
                mkdir(self::GOLDEN);
            }
            file_put_contents($path, $actual);
            $this->addToAssertionCount(1);
            return;
        }
        $this->assertFileExists($path, "missing $path; run with UPDATE_GOLDEN=1 vendor/bin/phpunit tests/GoldenTest.php");
        $this->assertSame((string) file_get_contents($path), $actual, "$scenario report changed");
    }

    public function testNoStaleSnapshots(): void
    {
        $stale = [];
        foreach (glob(self::GOLDEN . '/*.txt') ?: [] as $path) {
            $stem = basename($path, '.txt');
            if (!array_key_exists($stem, self::SCENARIOS)) {
                $stale[] = $stem;
            }
        }
        $this->assertSame([], $stale);
    }

    public function testFormatsAgree(): void
    {
        $args = array_slice(self::cliArgs('debian'), 0, -2);
        [, $out] = Helpers::runCli(...array_merge($args, ['--format', 'json']));
        $findings = json_decode($out, true, 512, JSON_THROW_ON_ERROR)['findings'];
        [, $out] = Helpers::runCli(...array_merge($args, ['--format', 'sarif']));
        $results = json_decode($out, true, 512, JSON_THROW_ON_ERROR)['runs'][0]['results'];
        $this->assertSame(array_column($findings, 'rule_id'), array_column($results, 'ruleId'));
        $ruleIds = array_values(array_unique(array_column($findings, 'rule_id')));
        [, $out] = Helpers::runCli(...array_merge($args, ['--format', 'markdown']));
        foreach ($ruleIds as $ruleId) {
            $this->assertStringContainsString("| $ruleId |", $out);
        }
        [, $out] = Helpers::runCli(...array_merge($args, ['--format', 'text', '--no-color', '--min-severity', 'info']));
        $this->assertStringNotContainsString("\033[", $out);
        foreach ($ruleIds as $ruleId) {
            $this->assertStringContainsString($ruleId, $out);
        }
    }
}

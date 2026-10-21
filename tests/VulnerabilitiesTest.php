<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Auditor;
use PhpIniAudit\Confidence;
use PhpIniAudit\CveData;
use PhpIniAudit\Discoverer;
use PhpIniAudit\EffectiveConfig;
use PhpIniAudit\FileSystem;
use PhpIniAudit\Finding;
use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Rules\Version\DisclosedCves;
use PhpIniAudit\Rules\Version\UnsupportedBranch;
use PhpIniAudit\Severity;
use PhpIniAudit\VersionEvidence;
use PhpIniAudit\VersionFinder;
use PhpIniAudit\Versions;
use PHPUnit\Framework\TestCase;

final class VulnerabilitiesTest extends TestCase
{
    private static function advisory(string $cve): Advisory
    {
        $advisory = Registry::advisory($cve);
        if ($advisory === null) {
            throw new \LogicException("no advisory $cve");
        }
        return $advisory;
    }

    /** @param list<int> $version */
    private static function context(array $version, ?string $versionSource = null, bool $backports = false): Context
    {
        $ctx = new Context(new EffectiveConfig([]), 'fpm', 'production', $version);
        $ctx->versionSource = $versionSource;
        $ctx->versionBackports = $backports;
        return $ctx;
    }

    /** @param iterable<Hit> $hits */
    private static function messages(iterable $hits): string
    {
        $messages = [];
        foreach ($hits as $hit) {
            $messages[] = $hit->message;
        }
        return implode(' ', $messages);
    }

    // Advisory status

    public function testPatchLevels(): void
    {
        $cgi = self::advisory('CVE-2024-4577');
        $this->assertSame('affected', $cgi->status([8, 3, 7]));
        $this->assertSame('fixed', $cgi->status([8, 3, 8]));
        $this->assertSame('possible', $cgi->status([8, 3]));
        $this->assertSame('fixed', $cgi->status([8, 4, 0]));
        $this->assertSame('untracked', $cgi->status([8, 0, 30]));
    }

    public function testEndOfLifeBranchBetweenFixesIsAffected(): void
    {
        $wrapper = self::advisory('CVE-2026-91766');
        $this->assertSame('affected', $wrapper->status([8, 2, 33]));
        $multipart = self::advisory('CVE-2023-0662');
        $this->assertSame('affected', $multipart->status([8, 1, 15]));
        $this->assertSame('8.1.16', $multipart->fixedFor([8, 1, 15]));
    }

    // End of life

    /**
     * @param list<int> $version
     * @return list<Hit>
     */
    private static function eolHits(array $version, string $today): array
    {
        $hits = (new UnsupportedBranch())->checkOn(self::context($version), new \DateTimeImmutable($today));
        return is_array($hits) ? $hits : iterator_to_array($hits, false);
    }

    public function testEndOfLifeDates(): void
    {
        $this->assertStringContainsString('ended on 2023-11-26', self::eolHits([8, 0, 30], '2026-01-01')[0]->message);
        $warning = self::eolHits([8, 2], '2026-10-21')[0];
        $this->assertSame(Severity::LOW, $warning->severity);
        $this->assertSame([], self::eolHits([8, 4], '2026-10-21'));
        $this->assertSame(Severity::CRITICAL, self::eolHits([5, 4, 45], '2026-01-01')[0]->severity);
    }

    // Disclosed CVEs

    /**
     * @param list<int> $version
     * @return list<Hit>
     */
    private static function cveHits(array $version, ?string $versionSource = null, bool $backports = false): array
    {
        $hits = (new DisclosedCves())->check(self::context($version, $versionSource, $backports));
        return is_array($hits) ? $hits : iterator_to_array($hits, false);
    }

    public function testListsCvesFixedLaterInBranch(): void
    {
        $hit = self::cveHits([8, 3, 34])[0];
        $this->assertStringContainsString('CVE-2026-91767', $hit->message);
        $this->assertStringContainsString('all fixed by 8.3.', $hit->message);
        $this->assertStringNotContainsString('CVE-2026-91766', $hit->message, 'config-dependent CVEs have their own rule');
        $listed = explode(', ', explode(': ', $hit->message, 2)[1]);
        $severities = [];
        foreach (CveData::DISCLOSED as [$cve, $severity]) {
            if (in_array($cve, $listed, true)) {
                $severities[] = $severity;
            }
        }
        $this->assertSame(max($severities), $hit->severity);
        $this->assertStringNotContainsString('CVE-2026-91767', self::messages(self::cveHits([8, 3, 35])));
    }

    public function testBranchWithoutListedFix(): void
    {
        $this->assertStringNotContainsString('CVE-2021-21708', self::messages(self::cveHits([8, 0, 30])));
    }

    public function testNeedsPatchLevel(): void
    {
        $this->assertSame([], self::cveHits([8, 3]));
        $this->assertSame([], self::cveHits([8, 5, 999]));
    }

    public function testBackportsLowerConfidence(): void
    {
        $hit = self::cveHits([8, 2, 7], 'dpkg', true)[0];
        $this->assertSame(Confidence::LOW, $hit->confidence);
    }

    // Configuration gating

    public function testCveRequiresFeature(): void
    {
        $exposed = Helpers::auditIni("allow_url_fopen = On\n", [], ['phpVersion' => [8, 3, 6]]);
        $this->assertNotEmpty(Helpers::findingsFor($exposed, 'CVE-2025-1861'));
        $closed = Helpers::auditIni("allow_url_fopen = Off\n", [], ['phpVersion' => [8, 3, 6]]);
        $this->assertEmpty(Helpers::findingsFor($closed, 'CVE-2025-1861'));
        $patched = Helpers::auditIni("allow_url_fopen = On\n", [], ['phpVersion' => [8, 3, 19]]);
        $this->assertEmpty(Helpers::findingsFor($patched, 'CVE-2025-1861'));
    }

    public function testPoolCves(): void
    {
        $result = Helpers::auditIni('', ['pool.d/www.conf' => "[www]\nlisten = 127.0.0.1:9000\n"
            . "listen.allowed_clients = 127.0.0.1\npm.status_path = /status\n"
            . "catch_workers_output = yes\n"], ['phpVersion' => [8, 3, 10]]);
        foreach (['CVE-2026-91768', 'CVE-2026-6735', 'CVE-2024-9026'] as $cve) {
            $this->assertNotEmpty(Helpers::findingsFor($result, $cve), $cve);
        }
    }

    public function testUnknownPatchIsSummarised(): void
    {
        $result = Helpers::auditIni("allow_url_fopen = On\n", [], ['phpVersion' => [8, 3]]);
        $this->assertEmpty(Helpers::findingsFor($result, 'CVE-2025-1861'));
        $summary = Helpers::findingsFor($result, 'VULN-002')[0];
        $this->assertStringContainsString('CVE-2025-1861 (fixed in 8.3.19)', $summary->message);
    }

    public function testOomPathReportedEvenWhenMitigated(): void
    {
        $finite = Helpers::findingsFor(
            Helpers::auditIni("post_max_size = 512M\n", [], ['phpVersion' => [8, 4, 26]]),
            'CVE-2026-109618'
        )[0];
        $this->assertSame(Confidence::HIGH, $finite->confidence);
        $this->assertStringContainsString('post_max_size = 512M', $finite->message);
        $unlimited = Helpers::auditIni("memory_limit = -1\n", [], ['phpVersion' => [8, 4, 26]]);
        $this->assertSame(Confidence::MEDIUM, Helpers::findingsFor($unlimited, 'CVE-2026-109618')[0]->confidence);
        $this->assertSame(Severity::INFO, Helpers::findingsFor($unlimited, 'RES-001')[0]->severity);
        $this->assertEmpty(Helpers::findingsFor(Helpers::auditIni('', [], ['phpVersion' => [8, 4, 27]]), 'CVE-2026-109618'));
        $this->assertEmpty(Helpers::findingsFor(
            Helpers::auditIni('', [], ['phpVersion' => [8, 4, 26], 'sapi' => 'cli']),
            'CVE-2026-109618'
        ));
    }

    public function testStaleStatePaths(): void
    {
        $default = Helpers::findingsFor(Helpers::auditIni('', [], ['phpVersion' => [8, 5, 11]]), 'CVE-2026-109619')[0];
        $this->assertStringContainsString('session.upload_progress.enabled is On', $default->message);
        $this->assertStringContainsString('fatal_error_backtraces is On', $default->message);
        $older = Helpers::findingsFor(Helpers::auditIni('', [], ['phpVersion' => [8, 4, 26]]), 'CVE-2026-109619')[0];
        $this->assertStringNotContainsString('fatal_error_backtraces', $older->message);
        $closed = Helpers::auditIni(
            "session.upload_progress.enabled = 0\nfatal_error_backtraces = 0\n",
            [],
            ['phpVersion' => [8, 5, 11]]
        );
        $this->assertSame(Confidence::MEDIUM, Helpers::findingsFor($closed, 'CVE-2026-109619')[0]->confidence);
    }

    public function testUserIniCannotDisableUploadProgress(): void
    {
        $tmp = Helpers::tempDir();
        try {
            file_put_contents("$tmp/php.ini", "session.upload_progress.enabled = On\n");
            file_put_contents("$tmp/.user.ini", "session.upload_progress.enabled = 0\nsession.sid_length = 48\n");
            $fs = new FileSystem();
            $discovery = (new Discoverer($fs))->paths(["$tmp/php.ini", "$tmp/.user.ini"]);
            $options = Helpers::options(['sapi' => 'fpm', 'phpVersion' => [8, 4, 26], 'pathChecks' => false]);
            $result = (new Auditor($fs, $options))->run($discovery);
        } finally {
            Helpers::removeTree($tmp);
        }
        $late = array_values(array_filter(
            Helpers::findingsFor($result, 'CVE-2026-109619'),
            static function (Finding $f): bool {
                return strpos($f->target, '.user.ini') !== false;
            }
        ));
        $this->assertStringContainsString('applies after request parsing', $late[0]->message);
        $this->assertSame(Severity::MEDIUM, Helpers::findingsFor($result, 'CFG-010')[0]->severity);
    }

    public function testCookiePrefix(): void
    {
        $result = Helpers::auditIni("session.name = __Host-SID\n", [], ['phpVersion' => [8, 2, 17]]);
        $this->assertNotEmpty(Helpers::findingsFor($result, 'CVE-2024-2756'));
    }

    // Version finder

    /**
     * @param list<VersionEvidence> $evidence
     * @return list<string>
     */
    private static function found(array $evidence): array
    {
        $found = array_values(array_unique(array_map(static function (VersionEvidence $e): string {
            return Versions::formatVersion($e->version) . ($e->backports ? ' backports' : '');
        }, $evidence)));
        sort($found);
        return $found;
    }

    public function testVersionSources(): void
    {
        $root = Helpers::tempDir();
        try {
            Helpers::writeFile("$root/usr/include/php/20230831/main/php_version.h", "#define PHP_VERSION \"8.3.12\"\n");
            Helpers::writeFile("$root/lib/apk/db/installed", "P:php82\nV:8.2.20-r0\n\nP:musl\nV:1.2.4-r2\n");
            mkdir("$root/opt/homebrew/Cellar/php/8.4.3", 0777, true);
            mkdir("$root/opt/homebrew/opt", 0777, true);
            symlink('../Cellar/php/8.4.3', "$root/opt/homebrew/opt/php");
            $found = self::found((new VersionFinder(new FileSystem($root)))->collect());
            $this->assertSame(['8.2.20', '8.3.12', '8.4.3'], $found);
        } finally {
            Helpers::removeTree($root);
        }
    }

    public function testDpkgMarksBackports(): void
    {
        $found = (new VersionFinder(new FileSystem(Helpers::FIXTURES . '/debian')))->collect();
        $this->assertSame(['8.2.7 backports'], self::found($found));
    }

    public function testAmbiguousBranch(): void
    {
        $evidence = [new VersionEvidence([8, 2, 1], '/opt/a/x.h'), new VersionEvidence([8, 2, 9], '/opt/b/x.h')];
        $this->assertNull(Versions::pick($evidence, [8, 2]));
        $this->assertSame([8, 2, 9], Versions::pick($evidence, [8, 2], '/opt/b/etc/php.ini')->version);
    }

    public function testEqualPrefixIsAmbiguous(): void
    {
        $evidence = [new VersionEvidence([8, 2, 1], '/srv/a/x.h'), new VersionEvidence([8, 2, 9], '/srv/b/x.h')];
        $this->assertNull(Versions::pick($evidence, [8, 2], '/srv/etc/php.ini'));
    }

    public function testHomebrewKegs(): void
    {
        $evidence = [
            new VersionEvidence([8, 4, 12], '/opt/homebrew/opt/php-debug/include/php/main/php_version.h'),
            new VersionEvidence([8, 4, 25], '/opt/homebrew/opt/php@8.4/include/php/main/php_version.h'),
            new VersionEvidence([8, 5, 10], '/opt/homebrew/opt/php'),
        ];
        $pick = static function (string $ini, array $branch) use ($evidence): array {
            return Versions::pick($evidence, $branch, $ini)->version;
        };
        $this->assertSame([8, 4, 25], $pick('/opt/homebrew/etc/php/8.4/php.ini', [8, 4]));
        $this->assertSame([8, 4, 12], $pick('/opt/homebrew/etc/php/8.4-debug/php.ini', [8, 4]));
        $this->assertSame([8, 5, 10], $pick('/opt/homebrew/etc/php/8.5/php.ini', [8, 5]));
    }

    // Fixtures

    /** @return array<string, mixed> */
    private function report(string ...$argv): array
    {
        [$code, $out] = Helpers::runCli(...array_merge($argv, ['--format', 'json']));
        $this->assertSame(0, $code);
        return json_decode($out, true, 512, JSON_THROW_ON_ERROR);
    }

    public function testDockerHeaderVersion(): void
    {
        $report = $this->report('--root', Helpers::FIXTURES . '/docker');
        $this->assertSame('8.3.6', $report['targets'][0]['php_version']);
        $ids = array_column($report['findings'], 'rule_id');
        $this->assertContains('CVE-2025-1861', $ids);
        $this->assertContains('CVE-2024-8925', $ids);
        $this->assertNotContains('CVE-2024-8927', $ids);
    }

    public function testDebianBackportsLowerConfidence(): void
    {
        $report = $this->report('--root', Helpers::FIXTURES . '/debian');
        $cves = array_filter($report['findings'], static function (array $f): bool {
            return strpos($f['rule_id'], 'CVE-') === 0;
        });
        $this->assertNotEmpty($cves);
        foreach ($cves as $f) {
            $this->assertSame(Confidence::name(Confidence::LOW), $f['confidence']);
        }
    }

    public function testWindowsCgi(): void
    {
        $report = $this->report(Helpers::FIXTURES . '/windows-xampp/php.ini', '--php-version', '8.3.7');
        $matches = array_values(array_filter($report['findings'], static function (array $f): bool {
            return $f['rule_id'] === 'CVE-2024-4577';
        }));
        $this->assertNotEmpty($matches);
        $this->assertSame('critical', $matches[0]['severity']);
        $this->assertSame('medium', $matches[0]['confidence']);
    }
}

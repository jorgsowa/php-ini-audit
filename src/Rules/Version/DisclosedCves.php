<?php

namespace PhpIniAudit\Rules\Version;

use PhpIniAudit\Confidence;
use PhpIniAudit\CveData;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;
use PhpIniAudit\Versions;

final class DisclosedCves extends ConfigRule
{
    public const ID = 'VULN-003';
    public const TITLE = 'Publicly disclosed CVEs affect this PHP version';
    public const SEVERITY = Severity::HIGH;
    public const DESCRIPTION = 'PHP releases fix publicly disclosed vulnerabilities that do not depend on a particular '
        . 'setting (parsers, extensions, bundled libraries). The finding lists every CVE fixed in a later release of '
        . 'this branch and takes the severity of the worst one; end-of-life branches are covered by VULN-001. CVEs '
        . 'whose exposure depends on the configuration are reported under their own IDs instead.';
    public const RECOMMENDATION = 'Upgrade to the latest release of a supported PHP branch.';
    public const REFERENCES = ['https://www.php.net/ChangeLog-8.php',
        'https://github.com/php/php-src/security/advisories'];

    public function check(Context $ctx): iterable
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
            $patch = Versions::patchFor(Versions::fixesByBranch($fixed), $branch);
            if (Registry::advisory($cve) !== null || $patch === null || $version[2] >= $patch) {
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

    /** @return array{int, int} */
    private static function cveKey(string $cve): array
    {
        [, $year, $number] = explode('-', $cve);
        return [(int) $year, (int) $number];
    }
}

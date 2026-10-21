<?php

namespace PhpIniAudit\Rules\Version;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;
use PhpIniAudit\Versions;

final class UnsupportedBranch extends ConfigRule
{
    public const ID = 'VULN-001';
    public const TITLE = 'PHP branch without security support';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-1104';
    public const DESCRIPTION = 'Branches past their end of life receive no security fixes, so every vulnerability '
        . 'found after that date stays open. A branch nearing its end of life is reported early.';
    public const RECOMMENDATION = 'Upgrade to a supported PHP branch (see php.net/supported-versions.php).';
    public const REFERENCES = ['https://www.php.net/supported-versions.php', 'https://www.php.net/eol.php'];

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
    public const WARNING_DAYS = 180;

    public function check(Context $ctx): iterable
    {
        return $this->checkOn($ctx, new \DateTimeImmutable('today'));
    }

    /** @return iterable<Hit> */
    public function checkOn(Context $ctx, \DateTimeImmutable $today): iterable
    {
        $version = $ctx->phpVersion;
        if (!$version) {
            return;
        }
        $today = $today->setTime(0, 0);
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
        } elseif ($days <= self::WARNING_DAYS) {
            yield new Hit(
                "PHP {$branch[0]}.{$branch[1]} security support ends on $endText ($days days)",
                [],
                Severity::LOW
            );
        }
    }
}

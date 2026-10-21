<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Util;

/** A known CVE whose exposure depends on the configuration. */
final class Advisory
{
    public string $cve;
    public string $title;
    public int $severity;
    /** @var list<string> */
    public array $fixed;
    /** @var callable(Context): ?array (reason, evidence[, confidence]) or null when not exposed */
    public $condition;
    public string $description;
    public string $mitigation;
    public ?string $cwe = null;
    public string $scope = 'config';
    /** @var list<string>|null */
    public ?array $sapis = null;

    public function __construct(string $cve, string $title, int $severity, array $fixed, callable $condition,
        string $description, string $mitigation)
    {
        $this->cve = $cve;
        $this->title = $title;
        $this->severity = $severity;
        $this->fixed = $fixed;
        $this->condition = $condition;
        $this->description = $description;
        $this->mitigation = $mitigation;
    }

    /** @return list<array{list<int>, int}> [branch, patch] pairs */
    public function fixes(): array
    {
        return Vulnerabilities::fixesByBranch($this->fixed);
    }

    /** 'affected', 'possible' (patch level unknown), 'fixed' or 'untracked' (older than every listed fix). */
    public function status(array $version): string
    {
        $fixes = $this->fixes();
        $branch = [$version[0], $version[1]];
        $patch = Vulnerabilities::patchFor($fixes, $branch);
        if ($patch !== null) {
            if (count($version) < 3) {
                return 'possible';
            }
            return $version[2] < $patch ? 'affected' : 'fixed';
        }
        $branches = array_column($fixes, 0);
        $highest = $lowest = $branches[0];
        foreach ($branches as $candidate) {
            if (Util::compare($candidate, $highest) > 0) {
                $highest = $candidate;
            }
            if (Util::compare($candidate, $lowest) < 0) {
                $lowest = $candidate;
            }
        }
        if (Util::compare($branch, $highest) > 0) {
            return 'fixed';
        }
        if (Util::compare($branch, $lowest) < 0) {
            return 'untracked';
        }
        return 'affected';
    }

    public function fixedFor(array $version): string
    {
        $branch = [$version[0], $version[1]];
        $patch = Vulnerabilities::patchFor($this->fixes(), $branch);
        if ($patch !== null) {
            return "{$branch[0]}.{$branch[1]}.$patch";
        }
        return 'a supported branch (' . implode(', ', $this->fixed) . ')';
    }

    /** @return ?array */
    public function condition(Context $ctx): ?array
    {
        return ($this->condition)($ctx);
    }
}

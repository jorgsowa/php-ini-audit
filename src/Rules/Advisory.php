<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Util;
use PhpIniAudit\Versions;

/**
 * A known CVE whose exposure depends on the configuration. ID is the CVE, FIXED the releases with the fix (one per
 * branch, from php.net/ChangeLog-7.php and ChangeLog-8.php), and exposure() says whether this configuration reaches it.
 */
abstract class Advisory extends ConfigRule
{
    /** @var list<string> */
    public const FIXED = [];

    /** @var list<string> */
    public array $fixed;

    public function __construct()
    {
        parent::__construct();
        $this->fixed = static::FIXED;
        $this->description .= ' Fixed in PHP ' . implode(', ', $this->fixed) . '.';
        $this->references = ['https://nvd.nist.gov/vuln/detail/' . static::ID];
    }

    /** Why the configuration reaches the vulnerable code, or null when it does not. */
    abstract public function exposure(Context $ctx): ?Exposure;

    final public function check(Context $ctx): iterable
    {
        $version = $ctx->phpVersion;
        if (!$version || $this->status($version) !== 'affected') {
            return;
        }
        $exposure = $this->exposure($ctx);
        if ($exposure === null) {
            return;
        }
        $confidence = $exposure->confidence;
        $message = 'PHP ' . Versions::formatVersion($version) . ' is affected (fixed in ' . $this->fixedFor($version)
            . "); {$exposure->reason}";
        if ($ctx->versionBackports) {
            $message .= '; the distribution build may carry a backported fix';
            $confidence = Confidence::LOW;
        }
        yield new Hit($message, $exposure->evidence, null, $confidence);
    }

    /** @return list<array{list<int>, int}> [branch, patch] pairs */
    public function fixes(): array
    {
        return Versions::fixesByBranch($this->fixed);
    }

    /** 'affected', 'possible' (patch level unknown), 'fixed' or 'untracked' (older than every listed fix). */
    public function status(array $version): string
    {
        $fixes = $this->fixes();
        $branch = [$version[0], $version[1]];
        $patch = Versions::patchFor($fixes, $branch);
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

    /** Whether the version is, or may be, older than the fix; false when the version is unknown. */
    public function exposes(?array $version): bool
    {
        return $version && in_array($this->status($version), ['affected', 'possible'], true);
    }

    public function fixedFor(array $version): string
    {
        $branch = [$version[0], $version[1]];
        $patch = Versions::patchFor($this->fixes(), $branch);
        if ($patch !== null) {
            return "{$branch[0]}.{$branch[1]}.$patch";
        }
        return 'a supported branch (' . implode(', ', $this->fixed) . ')';
    }
}

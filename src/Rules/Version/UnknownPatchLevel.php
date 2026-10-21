<?php

namespace PhpIniAudit\Rules\Version;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Severity;
use PhpIniAudit\Versions;

final class UnknownPatchLevel extends ConfigRule
{
    public const ID = 'VULN-002';
    public const TITLE = 'Known vulnerabilities depend on the exact PHP version';
    public const SEVERITY = Severity::INFO;
    public const DESCRIPTION = 'Some known CVEs apply to this configuration, but the exact PHP patch version could not '
        . 'be read from the system (php_version.h, dpkg, apk or Homebrew), so the scanner cannot tell whether the fix '
        . 'is installed.';
    public const RECOMMENDATION = 'Pass --php-version X.Y.Z (from `php -v` run by you), or scan with --root so package '
        . 'metadata can be read.';

    public function check(Context $ctx): iterable
    {
        $version = $ctx->phpVersion;
        if ($version && count($version) >= 3) {
            return;
        }
        if ($ctx->pool !== null || $ctx->overlayKind !== null) {
            return;
        }
        $pending = [];
        foreach (Registry::advisories() as $advisory) {
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
                if ($advisory->exposure($context) !== null) {
                    $exposed = true;
                    break;
                }
            }
            if (!$exposed) {
                continue;
            }
            $needed = $version ? $advisory->fixedFor($version) : implode('/', $advisory->fixed);
            $pending[] = "{$advisory->id} (fixed in $needed)";
        }
        if ($pending) {
            $known = $version ? 'PHP ' . Versions::formatVersion($version) : 'PHP version unknown';
            yield new Hit("$known; this configuration is exposed to " . count($pending) . ' CVE(s) unless patched: '
                . implode(', ', $pending), [], null, Confidence::MEDIUM);
        }
    }
}

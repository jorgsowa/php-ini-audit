<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Severity;

final class FpmStatusPageXss extends Advisory
{
    public const ID = 'CVE-2026-6735';
    public const TITLE = 'XSS in the PHP-FPM status page';
    public const SEVERITY = Severity::MEDIUM;
    public const SCOPE = 'pool';
    public const CWE = 'CWE-79';
    public const FIXED = ['8.2.31', '8.3.31', '8.4.21', '8.5.6'];
    public const DESCRIPTION = 'The FPM status endpoint reflects request data without escaping in its HTML output.';
    public const RECOMMENDATION = 'Upgrade, or remove pm.status_path / restrict it to administrators.';

    public function exposure(Context $ctx): ?Exposure
    {
        $directive = $ctx->pool->settings['pm.status_path'] ?? null;
        if ($directive !== null && trim($directive->value) !== '') {
            return new Exposure("pm.status_path = {$directive->value}", [$directive]);
        }
        return null;
    }
}

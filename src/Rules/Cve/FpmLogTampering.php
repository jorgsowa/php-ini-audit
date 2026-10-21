<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Severity;

final class FpmLogTampering extends Advisory
{
    public const ID = 'CVE-2024-9026';
    public const TITLE = 'PHP-FPM worker output can alter log entries';
    public const SEVERITY = Severity::LOW;
    public const SCOPE = 'pool';
    public const CWE = 'CWE-117';
    public const FIXED = ['8.1.30', '8.2.24', '8.3.12'];
    public const DESCRIPTION = 'With catch_workers_output, a worker can emit messages that strip characters from log '
        . 'lines, hiding or forging log entries.';
    public const RECOMMENDATION = 'Upgrade, or disable catch_workers_output.';

    public function exposure(Context $ctx): ?Exposure
    {
        $directive = $ctx->pool->settings['catch_workers_output'] ?? null;
        if ($directive !== null && $directive->value !== ''
            && !in_array(strtolower($directive->value), ['no', '0', 'off', 'false'], true)) {
            return new Exposure('catch_workers_output is enabled', [$directive]);
        }
        return null;
    }
}

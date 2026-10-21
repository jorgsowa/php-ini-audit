<?php

namespace PhpIniAudit\Rules\Fpm;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\PoolRule;
use PhpIniAudit\Severity;

final class StatusEndpoint extends PoolRule
{
    public const ID = 'FPM-005';
    public const TITLE = 'Status or ping endpoint enabled';
    public const SEVERITY = Severity::LOW;
    public const CWE = 'CWE-200';
    public const DESCRIPTION = 'pm.status_path and ping.path expose pool internals (client IPs, request URIs) if the '
        . 'web server forwards them.';
    public const RECOMMENDATION = 'Remove them or restrict access in the web server.';

    public function check(Context $ctx): iterable
    {
        foreach (['pm.status_path', 'ping.path'] as $key) {
            $directive = $ctx->pool->settings[$key] ?? null;
            if ($directive !== null && trim($directive->value) !== '') {
                yield new Hit("$key = {$directive->value}", [$directive], null, Confidence::MEDIUM);
            }
        }
    }
}

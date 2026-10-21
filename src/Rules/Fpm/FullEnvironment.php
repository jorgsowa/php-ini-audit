<?php

namespace PhpIniAudit\Rules\Fpm;

use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\PoolRule;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

final class FullEnvironment extends PoolRule
{
    public const ID = 'FPM-006';
    public const TITLE = 'Full environment passed to PHP';
    public const SEVERITY = Severity::LOW;
    public const CWE = 'CWE-526';
    public const DESCRIPTION = 'clear_env = no gives PHP every environment variable of the FPM master.';
    public const RECOMMENDATION = 'Keep clear_env = yes and pass only needed variables with env[NAME].';

    public function check(Context $ctx): iterable
    {
        $directive = $ctx->pool->settings['clear_env'] ?? null;
        if ($directive !== null && !Values::toBool($directive->value)) {
            yield new Hit('clear_env = no', [$directive]);
        }
    }
}

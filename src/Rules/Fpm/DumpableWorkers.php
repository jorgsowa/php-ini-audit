<?php

namespace PhpIniAudit\Rules\Fpm;

use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\PoolRule;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

final class DumpableWorkers extends PoolRule
{
    public const ID = 'FPM-008';
    public const TITLE = 'Workers are dumpable';
    public const SEVERITY = Severity::LOW;
    public const CWE = 'CWE-528';
    public const DESCRIPTION = 'process.dumpable = yes allows core dumps and ptrace of workers by the same user, '
        . 'exposing secrets held in memory.';
    public const RECOMMENDATION = 'Keep process.dumpable = no.';

    public function check(Context $ctx): iterable
    {
        $directive = $ctx->pool->settings['process.dumpable'] ?? null;
        if ($directive !== null && Values::toBool($directive->value)) {
            yield new Hit('process.dumpable = yes', [$directive]);
        }
    }
}

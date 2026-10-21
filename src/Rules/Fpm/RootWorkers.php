<?php

namespace PhpIniAudit\Rules\Fpm;

use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\PoolRule;
use PhpIniAudit\Severity;

final class RootWorkers extends PoolRule
{
    public const ID = 'FPM-004';
    public const TITLE = 'Pool workers run as root';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-250';
    public const DESCRIPTION = 'Running PHP as root turns any application bug into full system compromise.';
    public const RECOMMENDATION = 'Run each pool as a dedicated unprivileged user and group.';

    public function check(Context $ctx): iterable
    {
        foreach (['user', 'group'] as $key) {
            $directive = $ctx->pool->settings[$key] ?? null;
            if ($directive !== null && in_array(trim($directive->value), ['root', '0'], true)) {
                yield new Hit("$key = {$directive->value}", [$directive]);
            }
        }
    }
}

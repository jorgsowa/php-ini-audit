<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class BuiltinDefaults extends ConfigRule
{
    public const ID = 'CFG-006';
    public const TITLE = 'No php.ini loaded: built-in defaults in effect';
    public const SEVERITY = Severity::MEDIUM;
    public const DESCRIPTION = 'Without php.ini, PHP runs with compiled-in defaults: display_errors = On, '
        . 'register_argc_argv = On, expose_php = On, enable_dl = On and no disable_functions. Official Docker images '
        . 'ship this way.';
    public const RECOMMENDATION = 'Copy php.ini-production to php.ini and adjust it.';

    public function check(Context $ctx): iterable
    {
        if ($ctx->defaultsReason !== null && $ctx->defaultsReason !== '') {
            yield new Hit($ctx->defaultsReason);
        }
    }
}

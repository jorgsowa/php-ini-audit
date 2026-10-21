<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class ExceptionArgumentsInTraces extends ConfigRule
{
    public const ID = 'ERR-005';
    public const TITLE = 'Function arguments included in stack traces';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['zend.exception_ignore_args'];
    public const PRODUCTION_ONLY = true;
    public const CWE = 'CWE-532';
    public const DESCRIPTION = 'With zend.exception_ignore_args = Off, exception traces carry argument values such as '
        . 'passwords and tokens into logs and error pages.';
    public const RECOMMENDATION = 'Set zend.exception_ignore_args = On in production.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('zend.exception_ignore_args');
        if ($ctx->versionBelow(7, 4) !== true && !$setting->asBool()) {
            yield new Hit('zend.exception_ignore_args is Off', [$setting]);
        }
    }
}

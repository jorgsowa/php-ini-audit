<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class ErrorsNotLogged extends ConfigRule
{
    public const ID = 'ERR-003';
    public const TITLE = 'Errors are not logged';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['log_errors'];
    public const CWE = 'CWE-778';
    public const DESCRIPTION = 'Without log_errors, probing and exploitation attempts that trigger warnings leave no '
        . 'trace.';
    public const RECOMMENDATION = 'Set log_errors = On and configure error_log.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('log_errors');
        if (!$setting->asBool()) {
            yield new Hit('log_errors is Off', [$setting]);
        }
    }
}

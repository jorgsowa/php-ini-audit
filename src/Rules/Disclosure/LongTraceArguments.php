<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class LongTraceArguments extends ConfigRule
{
    public const ID = 'ERR-011';
    public const TITLE = 'Long string arguments kept in stack traces';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['zend.exception_string_param_max_len'];
    public const CWE = 'CWE-532';
    public const DESCRIPTION = 'Raising zend.exception_string_param_max_len stores more of each string argument in '
        . 'traces.';
    public const RECOMMENDATION = 'Keep the default (15) or lower.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('zend.exception_string_param_max_len');
        if ($setting->asInt() > 15) {
            yield new Hit($setting->describe(), [$setting]);
        }
    }
}

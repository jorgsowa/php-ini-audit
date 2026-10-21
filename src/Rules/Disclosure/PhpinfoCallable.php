<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class PhpinfoCallable extends ConfigRule
{
    public const ID = 'ERR-010';
    public const TITLE = 'phpinfo() callable';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['disable_functions'];
    public const SAPIS = Sapis::WEB;
    public const PRODUCTION_ONLY = true;
    public const CWE = 'CWE-200';
    public const DESCRIPTION = 'A forgotten phpinfo() page reveals configuration, paths, environment variables and '
        . 'cookies.';
    public const RECOMMENDATION = 'Add phpinfo to disable_functions in production.';

    public function check(Context $ctx): iterable
    {
        if (!isset($ctx->disabledFunctions()['phpinfo'])) {
            yield new Hit('phpinfo() is not disabled', [$ctx->get('disable_functions')], null, Confidence::LOW);
        }
    }
}

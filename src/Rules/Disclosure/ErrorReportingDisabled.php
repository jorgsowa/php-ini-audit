<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

final class ErrorReportingDisabled extends ConfigRule
{
    public const ID = 'ERR-006';
    public const TITLE = 'Error reporting disabled';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['error_reporting'];
    public const CWE = 'CWE-778';
    public const DESCRIPTION = 'error_reporting = 0 suppresses logging of every error, hiding attacks and bugs alike.';
    public const RECOMMENDATION = 'Use error_reporting = E_ALL and control visibility with display_errors.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('error_reporting');
        $level = Values::evalErrorReporting($setting->value);
        if ($level === 0) {
            yield new Hit('error_reporting evaluates to 0', [$setting]);
        }
    }
}

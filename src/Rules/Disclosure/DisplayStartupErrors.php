<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class DisplayStartupErrors extends ConfigRule
{
    public const ID = 'ERR-002';
    public const TITLE = 'Start-up errors displayed';
    public const SEVERITY = Severity::LOW;
    public const DEV_SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['display_startup_errors'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-209';
    public const DESCRIPTION = "display_startup_errors shows errors raised during PHP's start-up sequence in the "
        . 'output.';
    public const RECOMMENDATION = 'Set display_startup_errors = Off in production.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('display_startup_errors');
        if ($setting->asBool()) {
            yield new Hit('display_startup_errors is On', [$setting]);
        }
    }
}

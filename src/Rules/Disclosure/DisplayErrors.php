<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class DisplayErrors extends ConfigRule
{
    public const ID = 'ERR-001';
    public const TITLE = 'Errors displayed to visitors';
    public const SEVERITY = Severity::MEDIUM;
    public const DEV_SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['display_errors', 'html_errors'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-209';
    public const DESCRIPTION = 'display_errors prints warnings and stack traces into responses, disclosing paths, '
        . "queries, and sometimes credentials. PHP's built-in default is On when no php.ini is loaded.";
    public const RECOMMENDATION = 'Set display_errors = Off and log_errors = On in production.';
    public const REFERENCES = ['https://www.php.net/manual/en/errorfunc.configuration.php#ini.display-errors'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('display_errors');
        $text = strtolower($setting->text());
        if ($text === 'stderr') {
            return;
        }
        if ($text === 'stdout' || $setting->asBool()) {
            yield new Hit('display_errors is On', [$setting]);
        }
    }
}

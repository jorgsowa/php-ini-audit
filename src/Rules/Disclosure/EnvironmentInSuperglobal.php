<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class EnvironmentInSuperglobal extends ConfigRule
{
    public const ID = 'ERR-008';
    public const TITLE = 'Environment variables copied into $_ENV';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['variables_order'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-526';
    public const DESCRIPTION = "An 'E' in variables_order copies the process environment, often holding secrets, into "
        . '$_ENV where debug dumps and phpinfo() reveal it.';
    public const RECOMMENDATION = 'Use variables_order = "GPCS" and read configuration with getenv().';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('variables_order');
        if (strpos(strtoupper($setting->text()), 'E') !== false) {
            yield new Hit("{$setting->describe()} populates \$_ENV", [$setting], null, Confidence::MEDIUM);
        }
    }
}

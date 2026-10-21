<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class InputVars extends ConfigRule
{
    public const ID = 'RES-005';
    public const TITLE = 'max_input_vars raised or disabled';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['max_input_vars'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-407';
    public const DESCRIPTION = 'max_input_vars caps request variables and protects against hash-collision DoS '
        . '(CVE-2011-4885).';
    public const RECOMMENDATION = 'Keep max_input_vars at 1000-5000.';
    public const REFERENCES = ['https://nvd.nist.gov/vuln/detail/CVE-2011-4885'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('max_input_vars');
        $count = $setting->asInt();
        if ($count <= 0 || $count > 10000) {
            yield new Hit($setting->describe(), [$setting]);
        }
    }
}

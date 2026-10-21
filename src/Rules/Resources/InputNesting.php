<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class InputNesting extends ConfigRule
{
    public const ID = 'RES-006';
    public const TITLE = 'Deep input nesting allowed';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['max_input_nesting_level'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-674';
    public const DESCRIPTION = 'Deeply nested request arrays cost CPU and memory to parse.';
    public const RECOMMENDATION = 'Keep max_input_nesting_level at 64.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('max_input_nesting_level');
        if ($setting->asInt() > 256) {
            yield new Hit($setting->describe(), [$setting]);
        }
    }
}

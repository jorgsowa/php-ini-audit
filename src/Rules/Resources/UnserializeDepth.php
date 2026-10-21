<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class UnserializeDepth extends ConfigRule
{
    public const ID = 'RES-009';
    public const TITLE = 'unserialize() nesting depth unlimited';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['unserialize_max_depth'];
    public const CWE = 'CWE-674';
    public const DESCRIPTION = 'unserialize_max_depth = 0 lets deeply nested payloads exhaust the stack.';
    public const RECOMMENDATION = 'Keep unserialize_max_depth = 4096 or lower.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('unserialize_max_depth');
        if ($setting->asInt() <= 0) {
            yield new Hit('unserialize_max_depth is unlimited', [$setting]);
        }
    }
}

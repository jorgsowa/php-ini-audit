<?php

namespace PhpIniAudit\Rules\Encoding;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class FunctionOverloading extends ConfigRule
{
    public const ID = 'ENC-002';
    public const TITLE = 'mbstring function overloading enabled';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['mbstring.func_overload'];
    public const CWE = 'CWE-704';
    public const DESCRIPTION = 'mbstring.func_overload silently changes strlen()/substr() into multibyte versions, '
        . 'breaking binary-safe code such as cryptography and length checks. Removed in PHP 8.0.';
    public const RECOMMENDATION = 'Set mbstring.func_overload = 0 and call mb_* functions explicitly.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('mbstring.func_overload');
        if ($setting->asInt() === 0) {
            return;
        }
        $below8 = $ctx->versionBelow(8, 0);
        if ($below8 === false) {
            return;
        }
        yield new Hit($setting->describe(), [$setting], null, $below8 ? Confidence::HIGH : Confidence::LOW);
    }
}

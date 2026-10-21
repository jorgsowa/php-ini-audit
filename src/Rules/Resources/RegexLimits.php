<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class RegexLimits extends ConfigRule
{
    public const ID = 'RES-008';
    public const TITLE = 'Regular expression limits raised';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['pcre.backtrack_limit', 'pcre.recursion_limit'];
    public const CWE = 'CWE-1333';
    public const DESCRIPTION = 'Higher PCRE limits make catastrophic backtracking (ReDoS) and stack exhaustion '
        . 'crashes easier.';
    public const RECOMMENDATION = 'Keep pcre.backtrack_limit = 1000000 and pcre.recursion_limit = 100000.';

    public function check(Context $ctx): iterable
    {
        foreach (['pcre.backtrack_limit' => 1000000, 'pcre.recursion_limit' => 100000] as $name => $limit) {
            $setting = $ctx->get($name);
            if ($setting->asInt() > $limit) {
                yield new Hit("{$setting->describe()} (default $limit)", [$setting]);
            }
        }
    }
}

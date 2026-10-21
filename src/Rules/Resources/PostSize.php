<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class PostSize extends ConfigRule
{
    public const ID = 'RES-003';
    public const TITLE = 'Unlimited or very large POST bodies';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['post_max_size'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-770';
    public const DESCRIPTION = 'post_max_size = 0 removes the request body limit.';
    public const RECOMMENDATION = 'Set post_max_size slightly above the largest legitimate upload.';

    private const GIB = 1073741824;

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('post_max_size');
        $size = $setting->asBytes();
        if ($size === 0) {
            yield new Hit('post_max_size is unlimited (0)', [$setting]);
        } elseif ($size !== null && $size > self::GIB) {
            yield new Hit("{$setting->describe()} (> 1G)", [$setting], Severity::LOW);
        }
    }
}

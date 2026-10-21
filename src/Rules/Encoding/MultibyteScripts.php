<?php

namespace PhpIniAudit\Rules\Encoding;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class MultibyteScripts extends ConfigRule
{
    public const ID = 'ENC-003';
    public const TITLE = 'Multibyte script parsing enabled';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['zend.multibyte'];
    public const CWE = 'CWE-838';
    public const DESCRIPTION = 'zend.multibyte lets scripts be parsed in non-ASCII-compatible encodings such as '
        . 'Shift_JIS, which complicates reviewing code and can hide payloads.';
    public const RECOMMENDATION = 'Set zend.multibyte = Off unless legacy encodings are required.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('zend.multibyte');
        if ($setting->asBool()) {
            yield new Hit('zend.multibyte is On', [$setting]);
        }
    }
}

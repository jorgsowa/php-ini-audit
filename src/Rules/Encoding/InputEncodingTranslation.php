<?php

namespace PhpIniAudit\Rules\Encoding;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class InputEncodingTranslation extends ConfigRule
{
    public const ID = 'ENC-004';
    public const TITLE = 'Automatic input encoding translation';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['mbstring.encoding_translation'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-838';
    public const DESCRIPTION = 'mbstring.encoding_translation converts request input before the application validates '
        . 'it, which can undo validation done on raw bytes.';
    public const RECOMMENDATION = 'Set mbstring.encoding_translation = Off and convert explicitly.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('mbstring.encoding_translation');
        if ($setting->asBool()) {
            yield new Hit('mbstring.encoding_translation is On', [$setting]);
        }
    }
}

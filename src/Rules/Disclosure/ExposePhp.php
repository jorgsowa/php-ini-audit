<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class ExposePhp extends ConfigRule
{
    public const ID = 'ERR-004';
    public const TITLE = 'PHP version disclosed in HTTP headers';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['expose_php'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-200';
    public const DESCRIPTION = 'expose_php adds an X-Powered-By header with the exact PHP version, which helps '
        . 'attackers pick exploits.';
    public const RECOMMENDATION = 'Set expose_php = Off.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('expose_php');
        if ($setting->asBool()) {
            yield new Hit('expose_php is On', [$setting]);
        }
    }
}

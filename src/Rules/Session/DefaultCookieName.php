<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class DefaultCookieName extends ConfigRule
{
    public const ID = 'SESS-012';
    public const TITLE = 'Default session cookie name';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['session.name'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-200';
    public const DESCRIPTION = 'PHPSESSID identifies the backend as PHP.';
    public const RECOMMENDATION = 'Choose an application-specific session.name.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.name');
        if ($setting->text() === 'PHPSESSID') {
            yield new Hit('session.name is PHPSESSID', [$setting]);
        }
    }
}

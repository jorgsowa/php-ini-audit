<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class CookieWithoutHttpOnly extends ConfigRule
{
    public const ID = 'SESS-005';
    public const TITLE = 'Session cookie readable from JavaScript';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['session.cookie_httponly'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-1004';
    public const DESCRIPTION = 'Without HttpOnly, any XSS can read document.cookie and steal the session.';
    public const RECOMMENDATION = 'Set session.cookie_httponly = 1.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.cookie_httponly');
        if (!$setting->asBool()) {
            yield new Hit('session.cookie_httponly is Off', [$setting]);
        }
    }
}

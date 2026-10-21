<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class CookieWithoutSecure extends ConfigRule
{
    public const ID = 'SESS-006';
    public const TITLE = 'Session cookie sent over plain HTTP';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['session.cookie_secure'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-614';
    public const DESCRIPTION = 'Without the Secure flag the session cookie is sent over unencrypted connections and '
        . 'can be sniffed or injected.';
    public const RECOMMENDATION = 'Set session.cookie_secure = 1 on sites served over HTTPS.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.cookie_secure');
        if (!$setting->asBool()) {
            yield new Hit('session.cookie_secure is Off', [$setting], null, Confidence::MEDIUM);
        }
    }
}

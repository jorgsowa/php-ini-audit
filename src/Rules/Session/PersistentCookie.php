<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class PersistentCookie extends ConfigRule
{
    public const ID = 'SESS-013';
    public const TITLE = 'Persistent session cookie';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['session.cookie_lifetime'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-539';
    public const DESCRIPTION = 'A non-zero cookie_lifetime stores the session cookie on disk in the browser.';
    public const RECOMMENDATION = 'Use session.cookie_lifetime = 0 and handle "remember me" separately.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.cookie_lifetime');
        if ($setting->asInt() > 0) {
            yield new Hit("{$setting->describe()} seconds", [$setting]);
        }
    }
}

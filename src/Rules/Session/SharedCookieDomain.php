<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class SharedCookieDomain extends ConfigRule
{
    public const ID = 'SESS-014';
    public const TITLE = 'Session cookie shared with other hosts';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['session.cookie_domain'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-565';
    public const DESCRIPTION = 'A cookie_domain makes the session cookie visible to every subdomain, so one '
        . 'compromised subdomain can read or overwrite it.';
    public const RECOMMENDATION = 'Leave session.cookie_domain empty unless sessions must span subdomains.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.cookie_domain');
        if ($setting->text() !== '') {
            yield new Hit($setting->describe(), [$setting]);
        }
    }
}

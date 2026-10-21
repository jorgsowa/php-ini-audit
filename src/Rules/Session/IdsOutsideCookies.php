<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class IdsOutsideCookies extends ConfigRule
{
    public const ID = 'SESS-002';
    public const TITLE = 'Session IDs accepted outside cookies';
    public const SEVERITY = Severity::HIGH;
    public const DIRECTIVES = ['session.use_only_cookies'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-598';
    public const DESCRIPTION = 'session.use_only_cookies = 0 accepts session IDs from the URL, enabling fixation via '
        . 'links and leaking IDs through Referer headers and logs.';
    public const RECOMMENDATION = 'Set session.use_only_cookies = 1.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.use_only_cookies');
        if (!$setting->asBool()) {
            yield new Hit('session.use_only_cookies is Off', [$setting]);
        }
    }
}

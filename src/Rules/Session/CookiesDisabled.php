<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class CookiesDisabled extends ConfigRule
{
    public const ID = 'SESS-004';
    public const TITLE = 'Session cookies disabled';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['session.use_cookies'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-598';
    public const DESCRIPTION = 'session.use_cookies = 0 forces session IDs into URLs or breaks sessions entirely.';
    public const RECOMMENDATION = 'Set session.use_cookies = 1.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.use_cookies');
        if (!$setting->asBool()) {
            yield new Hit('session.use_cookies is Off', [$setting]);
        }
    }
}

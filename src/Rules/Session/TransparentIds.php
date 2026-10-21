<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class TransparentIds extends ConfigRule
{
    public const ID = 'SESS-003';
    public const TITLE = 'Transparent session IDs in URLs';
    public const SEVERITY = Severity::HIGH;
    public const DIRECTIVES = ['session.use_trans_sid'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-598';
    public const DESCRIPTION = 'session.use_trans_sid rewrites links to carry the session ID, which leaks through '
        . 'Referer, browser history, proxies and shared links.';
    public const RECOMMENDATION = 'Set session.use_trans_sid = 0.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.use_trans_sid');
        if ($setting->asBool()) {
            yield new Hit('session.use_trans_sid is On', [$setting]);
        }
    }
}

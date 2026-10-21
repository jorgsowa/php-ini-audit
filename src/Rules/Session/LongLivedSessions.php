<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class LongLivedSessions extends ConfigRule
{
    public const ID = 'SESS-011';
    public const TITLE = 'Long-lived sessions';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['session.gc_maxlifetime'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-613';
    public const DESCRIPTION = 'Session data is kept for gc_maxlifetime seconds of inactivity; long lifetimes widen '
        . 'the window for stolen session IDs.';
    public const RECOMMENDATION = 'Keep session.gc_maxlifetime at a few hours or less and implement absolute timeouts '
        . 'in the application.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.gc_maxlifetime');
        if ($setting->asInt() > 86400) {
            yield new Hit("{$setting->describe()} seconds (> 1 day)", [$setting]);
        }
    }
}

<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class StrictModeOff extends ConfigRule
{
    public const ID = 'SESS-001';
    public const TITLE = 'Uninitialised session IDs accepted';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['session.use_strict_mode'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-384';
    public const DESCRIPTION = 'Without strict mode PHP adopts any session ID a client presents, enabling session '
        . 'fixation.';
    public const RECOMMENDATION = 'Set session.use_strict_mode = 1.';
    public const REFERENCES = ['https://www.php.net/manual/en/session.security.ini.php'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.use_strict_mode');
        if (!$setting->asBool()) {
            yield new Hit('session.use_strict_mode is Off', [$setting]);
        }
    }
}

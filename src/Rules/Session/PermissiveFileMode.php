<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

final class PermissiveFileMode extends ConfigRule
{
    public const ID = 'SESS-010';
    public const TITLE = 'Session files created with permissive mode';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['session.save_path'];
    public const CWE = 'CWE-276';
    public const DESCRIPTION = 'session.save_path = "N;MODE;/path" sets the file mode of session files; group or '
        . 'world access exposes session contents.';
    public const RECOMMENDATION = 'Use mode 600 (the default).';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('session.save_path');
        $parts = explode(';', $setting->text());
        if (count($parts) !== 3) {
            return;
        }
        $shown = trim($parts[1]);
        $mode = Values::parseOctal($shown);
        if ($mode === null) {
            return;
        }
        if ($mode & 0007) {
            yield new Hit("session files are created with mode $shown", [$setting]);
        } elseif ($mode & 0070) {
            yield new Hit("session files are created with mode $shown", [$setting], Severity::LOW);
        }
    }
}

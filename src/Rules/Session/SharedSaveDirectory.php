<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;
use PhpIniAudit\Stat;
use PhpIniAudit\Util;
use PhpIniAudit\Values;

final class SharedSaveDirectory extends ConfigRule
{
    public const ID = 'SESS-009';
    public const TITLE = 'Session files stored in a shared or listable directory';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['session.save_path', 'session.save_handler'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-552';
    public const DESCRIPTION = 'Session files are named after the session ID. In a directory other users can list '
        . '(such as /tmp), they can harvest IDs and hijack sessions, or plant crafted session files.';
    public const RECOMMENDATION = 'Use a dedicated session directory such as /var/lib/php/sessions with mode 1733 or '
        . '0700.';

    private const SHARED_TEMP = ['', '/tmp', '/var/tmp', '/dev/shm'];

    public function check(Context $ctx): iterable
    {
        $handler = $ctx->get('session.save_handler');
        if (strtolower($handler->text()) !== 'files') {
            return;
        }
        $setting = $ctx->get('session.save_path');
        $directory = Values::sessionDir($setting->text());
        if ($ctx->paths !== null && Util::startsWith($directory, '/')) {
            $info = $ctx->paths->fs->stat($directory);
            if ($info !== null && ($info['mode'] & Stat::S_IROTH)) {
                yield new Hit("$directory can be listed by every local user", [$setting]);
                return;
            }
            if ($info !== null) {
                return;
            }
        }
        if (in_array($directory, self::SHARED_TEMP, true)) {
            $shown = $directory !== '' ? $directory : 'the system temp directory';
            yield new Hit("session files are written to $shown", [$setting], null, Confidence::MEDIUM);
        }
    }
}

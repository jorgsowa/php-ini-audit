<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class SessionUploadProgress extends ConfigRule
{
    public const ID = 'EXEC-017';
    public const TITLE = 'Session upload progress writes request data into session files';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['session.upload_progress.enabled', 'session.upload_progress.cleanup'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-98';
    public const DESCRIPTION = 'With upload progress enabled, any multipart request stores attacker-controlled data '
        . 'in a session file, which turns a local file inclusion into code execution even without a session.';
    public const RECOMMENDATION = 'Set session.upload_progress.enabled = Off unless upload progress bars are used; '
        . 'never disable session.upload_progress.cleanup.';

    public function check(Context $ctx): iterable
    {
        $enabled = $ctx->get('session.upload_progress.enabled');
        if (!$enabled->asBool()) {
            return;
        }
        $cleanup = $ctx->get('session.upload_progress.cleanup');
        if (!$cleanup->asBool()) {
            yield new Hit(
                'upload progress is enabled and cleanup is Off, so the data persists in the session file',
                [$enabled, $cleanup],
                Severity::MEDIUM
            );
        } else {
            yield new Hit('session.upload_progress.enabled is On', [$enabled], null, Confidence::MEDIUM);
        }
    }
}

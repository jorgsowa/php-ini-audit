<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class FileUploadsEnabled extends ConfigRule
{
    public const ID = 'FS-009';
    public const TITLE = 'HTTP file uploads enabled';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['file_uploads'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-434';
    public const DESCRIPTION = 'file_uploads lets every script receive files; disable it on hosts that never accept '
        . 'uploads.';
    public const RECOMMENDATION = 'Set file_uploads = Off where uploads are not needed.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('file_uploads');
        if ($setting->asBool()) {
            yield new Hit('file_uploads is On', [$setting], null, Confidence::LOW);
        }
    }
}

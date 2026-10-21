<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class FileUploadCount extends ConfigRule
{
    public const ID = 'RES-007';
    public const TITLE = 'Many files per request accepted';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['max_file_uploads'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-770';
    public const DESCRIPTION = 'Each uploaded file costs a temp file and file descriptor.';
    public const RECOMMENDATION = "Keep max_file_uploads at 20 or the application's real need.";

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('max_file_uploads');
        if ($setting->asInt() > 100) {
            yield new Hit($setting->describe(), [$setting]);
        }
    }
}

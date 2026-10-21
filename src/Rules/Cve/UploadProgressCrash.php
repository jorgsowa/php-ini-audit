<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class UploadProgressCrash extends Advisory
{
    public const ID = 'CVE-2020-7062';
    public const TITLE = 'Crash in session upload progress';
    public const SEVERITY = Severity::MEDIUM;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-476';
    public const FIXED = ['7.2.28', '7.3.15', '7.4.3'];
    public const DESCRIPTION = 'A crafted upload with session upload progress enabled dereferences a NULL pointer and '
        . 'crashes the worker.';
    public const RECOMMENDATION = 'Upgrade, or set session.upload_progress.enabled = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        $setting = $ctx->get('session.upload_progress.enabled');
        if ($ctx->isWeb() && $setting->asBool()) {
            return new Exposure('session.upload_progress.enabled is On', [$setting]);
        }
        return null;
    }
}

<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class UploadTempFileLeak extends Advisory
{
    public const ID = 'CVE-2019-11048';
    public const TITLE = 'Upload temp files left behind by long names';
    public const SEVERITY = Severity::MEDIUM;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-190';
    public const FIXED = ['7.2.31', '7.3.18', '7.4.6'];
    public const DESCRIPTION = 'Long file or variable names in multipart requests exhaust memory and leave temporary '
        . 'upload files on disk.';
    public const RECOMMENDATION = 'Upgrade.';

    public function exposure(Context $ctx): ?Exposure
    {
        $setting = $ctx->get('file_uploads');
        if ($ctx->isWeb() && $setting->asBool()) {
            return new Exposure('file_uploads is On', [$setting]);
        }
        return null;
    }
}

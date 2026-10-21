<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class MultipartDos extends Advisory
{
    public const ID = 'CVE-2023-0662';
    public const TITLE = 'Denial of service through multipart request bodies';
    public const SEVERITY = Severity::MEDIUM;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-400';
    public const FIXED = ['8.0.28', '8.1.16', '8.2.3'];
    public const DESCRIPTION = 'Requests with many multipart parts consume excessive CPU; the fix introduced '
        . 'max_multipart_body_parts.';
    public const RECOMMENDATION = 'Upgrade and keep max_input_vars/max_file_uploads modest.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::postReading($ctx);
    }
}

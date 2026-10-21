<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class MultipartParsing extends Advisory
{
    public const ID = 'CVE-2024-8925';
    public const TITLE = 'Erroneous parsing of multipart form data';
    public const SEVERITY = Severity::MEDIUM;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-436';
    public const FIXED = ['8.1.30', '8.2.24', '8.3.12'];
    public const DESCRIPTION = 'Malformed multipart boundaries are parsed inconsistently with upstream proxies and '
        . 'WAFs, letting attackers smuggle form fields past filtering.';
    public const RECOMMENDATION = 'Upgrade.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::postReading($ctx);
    }
}

<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class HttpFoldedHeaders extends Advisory
{
    public const ID = 'CVE-2025-1217';
    public const TITLE = 'HTTP wrapper mishandles folded headers';
    public const SEVERITY = Severity::LOW;
    public const CWE = 'CWE-436';
    public const FIXED = ['8.1.32', '8.2.28', '8.3.19', '8.4.5'];
    public const DESCRIPTION = "PHP's http:// stream wrapper does not handle folded headers, so response headers can "
        . 'be misinterpreted.';
    public const RECOMMENDATION = 'Upgrade, or set allow_url_fopen = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::urlFopen($ctx);
    }
}

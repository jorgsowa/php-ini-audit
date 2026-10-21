<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class HttpHeaderWithoutColon extends Advisory
{
    public const ID = 'CVE-2025-1734';
    public const TITLE = 'HTTP wrapper accepts headers without a colon';
    public const SEVERITY = Severity::LOW;
    public const CWE = 'CWE-436';
    public const FIXED = ['8.1.32', '8.2.28', '8.3.19', '8.4.5'];
    public const DESCRIPTION = "PHP's http:// stream wrapper accepts malformed response headers, enabling response "
        . 'confusion.';
    public const RECOMMENDATION = 'Upgrade, or set allow_url_fopen = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::urlFopen($ctx);
    }
}

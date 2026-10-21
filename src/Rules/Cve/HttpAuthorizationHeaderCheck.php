<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class HttpAuthorizationHeaderCheck extends Advisory
{
    public const ID = 'CVE-2025-1736';
    public const TITLE = 'HTTP wrapper header check may omit headers';
    public const SEVERITY = Severity::MEDIUM;
    public const CWE = 'CWE-20';
    public const FIXED = ['8.1.32', '8.2.28', '8.3.19', '8.4.5'];
    public const DESCRIPTION = "PHP's http:// stream wrapper may miss user-supplied Authorization headers and send "
        . 'unintended headers.';
    public const RECOMMENDATION = 'Upgrade, or set allow_url_fopen = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::urlFopen($ctx);
    }
}

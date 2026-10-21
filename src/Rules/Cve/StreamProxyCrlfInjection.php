<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class StreamProxyCrlfInjection extends Advisory
{
    public const ID = 'CVE-2024-11234';
    public const TITLE = 'CRLF injection through stream proxy configuration';
    public const SEVERITY = Severity::MEDIUM;
    public const CWE = 'CWE-93';
    public const FIXED = ['8.1.31', '8.2.26', '8.3.14'];
    public const DESCRIPTION = "PHP's http:// stream wrapper with a proxy configured allows CRLF injection in the "
        . 'request URI.';
    public const RECOMMENDATION = 'Upgrade, or set allow_url_fopen = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::urlFopen($ctx);
    }
}

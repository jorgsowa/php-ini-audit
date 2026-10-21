<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class HttpRedirectCredentialLeak extends Advisory
{
    public const ID = 'CVE-2026-91766';
    public const TITLE = 'HTTP wrapper leaks credentials across origins on redirect';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-200';
    public const FIXED = ['8.2.34', '8.3.35', '8.4.26', '8.5.11'];
    public const DESCRIPTION = "PHP's http:// stream wrapper forwards credentials to a different origin when "
        . 'following redirects.';
    public const RECOMMENDATION = 'Upgrade, or set allow_url_fopen = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::urlFopen($ctx);
    }
}

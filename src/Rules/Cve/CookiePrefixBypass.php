<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class CookiePrefixBypass extends Advisory
{
    public const ID = 'CVE-2024-2756';
    public const TITLE = '__Host-/__Secure- cookie prefix bypass';
    public const SEVERITY = Severity::MEDIUM;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-565';
    public const FIXED = ['8.1.28', '8.2.18', '8.3.6'];
    public const DESCRIPTION = 'Cookie name mangling lets a non-secure origin set cookies that PHP reads as '
        . '__Host-/__Secure- cookies (incomplete fix of CVE-2022-31629).';
    public const RECOMMENDATION = 'Upgrade.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::prefixedSessionCookie($ctx);
    }
}

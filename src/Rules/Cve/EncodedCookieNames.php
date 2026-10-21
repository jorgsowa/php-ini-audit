<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class EncodedCookieNames extends Advisory
{
    public const ID = 'CVE-2020-7070';
    public const TITLE = 'Encoded cookie names allow __Host- spoofing';
    public const SEVERITY = Severity::MEDIUM;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-565';
    public const FIXED = ['7.2.34', '7.3.23', '7.4.11'];
    public const DESCRIPTION = 'PHP URL-decodes cookie names, so a crafted name is read as a __Host- cookie.';
    public const RECOMMENDATION = 'Upgrade.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::prefixedSessionCookie($ctx);
    }
}

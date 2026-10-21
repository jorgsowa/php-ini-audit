<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class HostCookieSpoofing extends Advisory
{
    public const ID = 'CVE-2022-31629';
    public const TITLE = '__Host- cookie names can be spoofed';
    public const SEVERITY = Severity::MEDIUM;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-565';
    public const FIXED = ['7.4.32', '8.0.24', '8.1.11'];
    public const DESCRIPTION = 'HTTP variable name mangling lets an attacker set cookies that PHP treats as __Host- '
        . 'prefixed.';
    public const RECOMMENDATION = 'Upgrade.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::prefixedSessionCookie($ctx);
    }
}

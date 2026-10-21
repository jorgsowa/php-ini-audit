<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class CgiWindowsArgumentInjectionBypass extends Advisory
{
    public const ID = 'CVE-2024-8926';
    public const TITLE = 'Bypass of the CVE-2024-4577 fix';
    public const SEVERITY = Severity::CRITICAL;
    public const SAPIS = Sapis::CGI;
    public const CWE = 'CWE-88';
    public const FIXED = ['8.1.30', '8.2.24', '8.3.12'];
    public const DESCRIPTION = 'Certain Windows code pages still allow php-cgi argument injection after the '
        . 'CVE-2024-4577 fix.';
    public const RECOMMENDATION = 'Upgrade; do not expose php-cgi on Windows.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::windowsCgi($ctx);
    }
}

<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class CgiWindowsArgumentInjection extends Advisory
{
    public const ID = 'CVE-2024-4577';
    public const TITLE = 'php-cgi argument injection on Windows';
    public const SEVERITY = Severity::CRITICAL;
    public const SAPIS = Sapis::CGI;
    public const CWE = 'CWE-78';
    public const FIXED = ['8.1.29', '8.2.20', '8.3.8'];
    public const DESCRIPTION = "Windows 'Best-Fit' character conversion lets a soft hyphen in the query string become "
        . 'a php-cgi command-line option, giving remote code execution (exploited in the wild, e.g. default XAMPP).';
    public const RECOMMENDATION = 'Upgrade; until then do not expose php-cgi (use PHP-FPM or mod_php).';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::windowsCgi($ctx);
    }
}

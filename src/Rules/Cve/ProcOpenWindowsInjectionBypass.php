<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class ProcOpenWindowsInjectionBypass extends Advisory
{
    public const ID = 'CVE-2024-5585';
    public const TITLE = 'Bypass of the CVE-2024-1874 fix';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-78';
    public const FIXED = ['8.1.29', '8.2.20', '8.3.8'];
    public const DESCRIPTION = 'Trailing spaces in the command name bypass the CVE-2024-1874 escaping fix for '
        . 'proc_open() on Windows.';
    public const RECOMMENDATION = 'Upgrade, or add proc_open to disable_functions if unused.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::windowsProcOpen($ctx);
    }
}

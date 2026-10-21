<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class ProcOpenWindowsInjection extends Advisory
{
    public const ID = 'CVE-2024-1874';
    public const TITLE = 'Command injection through proc_open() on Windows';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-78';
    public const FIXED = ['8.1.28', '8.2.18', '8.3.6'];
    public const DESCRIPTION = 'Array-form proc_open() commands are not escaped correctly for .bat/.cmd files on '
        . 'Windows.';
    public const RECOMMENDATION = 'Upgrade, or add proc_open to disable_functions if unused.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::windowsProcOpen($ctx);
    }
}

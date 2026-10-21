<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class FpmPrivilegeEscalation extends Advisory
{
    public const ID = 'CVE-2021-21703';
    public const TITLE = 'PHP-FPM local privilege escalation to root';
    public const SEVERITY = Severity::HIGH;
    public const SAPIS = Sapis::FPM;
    public const CWE = 'CWE-787';
    public const FIXED = ['7.3.32', '7.4.25', '8.0.12'];
    public const DESCRIPTION = 'A compromised FPM worker can write to shared memory of the root master process and '
        . 'escalate to root.';
    public const RECOMMENDATION = 'Upgrade.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::fpm($ctx);
    }
}

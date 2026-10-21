<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class FpmOpcacheAccessBypass extends Advisory
{
    public const ID = 'CVE-2018-10545';
    public const TITLE = 'FPM workers can bypass OPcache access controls';
    public const SEVERITY = Severity::MEDIUM;
    public const SAPIS = Sapis::FPM;
    public const CWE = 'CWE-284';
    public const FIXED = ['7.0.29', '7.1.16', '7.2.4'];
    public const DESCRIPTION = "Dumpable FPM child processes let one pool read another pool's OPcache data via ptrace.";
    public const RECOMMENDATION = 'Upgrade; keep process.dumpable = no.';

    public function exposure(Context $ctx): ?Exposure
    {
        if ($ctx->usesFpm() && count($ctx->pools) > 1) {
            return new Exposure(count($ctx->pools) . ' FPM pools share one OPcache');
        }
        return null;
    }
}

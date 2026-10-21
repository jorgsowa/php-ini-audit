<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class FpmPathInfoUnderflow extends Advisory
{
    public const ID = 'CVE-2019-11043';
    public const TITLE = 'PHP-FPM env_path_info underflow (remote code execution)';
    public const SEVERITY = Severity::CRITICAL;
    public const SAPIS = Sapis::FPM;
    public const CWE = 'CWE-787';
    public const FIXED = ['7.1.33', '7.2.24', '7.3.11'];
    public const DESCRIPTION = 'With nginx configurations that use fastcgi_split_path_info with a regex that can be '
        . 'broken by a newline, a crafted URL corrupts FPM memory and leads to remote code execution (exploited in '
        . 'the wild).';
    public const RECOMMENDATION = 'Upgrade; add try_files $fastcgi_script_name =404 before fastcgi_pass.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::fpm($ctx);
    }
}

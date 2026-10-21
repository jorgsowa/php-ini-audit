<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class ForceRedirectBypass extends Advisory
{
    public const ID = 'CVE-2024-8927';
    public const TITLE = 'cgi.force_redirect bypass';
    public const SEVERITY = Severity::HIGH;
    public const SAPIS = Sapis::CGI;
    public const CWE = 'CWE-284';
    public const FIXED = ['8.1.30', '8.2.24', '8.3.12'];
    public const DESCRIPTION = 'An environment variable collision lets requests bypass the cgi.force_redirect '
        . 'protection and invoke php-cgi directly.';
    public const RECOMMENDATION = 'Upgrade; do not expose php-cgi directly.';

    public function exposure(Context $ctx): ?Exposure
    {
        $setting = $ctx->get('cgi.force_redirect');
        $confidence = Exposures::cgiConfidence($ctx);
        if ($confidence !== null && $setting->asBool()) {
            return new Exposure('php-cgi relies on cgi.force_redirect', [$setting], $confidence);
        }
        return null;
    }
}

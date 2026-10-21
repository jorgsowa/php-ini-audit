<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class LibxmlRedirectContentType extends Advisory
{
    public const ID = 'CVE-2025-1219';
    public const TITLE = 'libxml uses the wrong content type after redirects';
    public const SEVERITY = Severity::LOW;
    public const CWE = 'CWE-436';
    public const FIXED = ['8.1.32', '8.2.28', '8.3.19', '8.4.5'];
    public const DESCRIPTION = 'Remote documents loaded by DOM/SimpleXML through redirects are parsed with the wrong '
        . 'charset.';
    public const RECOMMENDATION = 'Upgrade, or set allow_url_fopen = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::urlFopen($ctx);
    }
}

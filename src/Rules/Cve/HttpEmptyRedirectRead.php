<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Support\Exposures;
use PhpIniAudit\Severity;

final class HttpEmptyRedirectRead extends Advisory
{
    public const ID = 'CVE-2026-93682';
    public const TITLE = 'HTTP wrapper out-of-bounds read on empty redirect';
    public const SEVERITY = Severity::MEDIUM;
    public const CWE = 'CWE-125';
    public const FIXED = ['8.2.34', '8.3.35', '8.4.26', '8.5.11'];
    public const DESCRIPTION = "A redirect with an empty Location header makes PHP's http:// stream wrapper read out "
        . 'of bounds.';
    public const RECOMMENDATION = 'Upgrade, or set allow_url_fopen = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        return Exposures::urlFopen($ctx);
    }
}

<?php

namespace PhpIniAudit\Rules\Opcache;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class UnrestrictedApi extends ConfigRule
{
    public const ID = 'OPC-002';
    public const TITLE = 'OPcache API not restricted';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['opcache.restrict_api'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-284';
    public const DESCRIPTION = 'Any script can call opcache_get_status() (revealing every cached path) or '
        . 'opcache_reset(). This matters on shared hosting.';
    public const RECOMMENDATION = 'Set opcache.restrict_api to the path prefix of trusted admin scripts.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('opcache.restrict_api');
        if ($setting->text() === '') {
            yield new Hit('opcache.restrict_api is empty', [$setting], null, Confidence::LOW);
        }
    }
}

<?php

namespace PhpIniAudit\Rules\Cgi;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class ForceRedirectOff extends ConfigRule
{
    public const ID = 'CGI-001';
    public const TITLE = 'php-cgi callable without web-server redirect';
    public const SEVERITY = Severity::HIGH;
    public const DIRECTIVES = ['cgi.force_redirect'];
    public const SAPIS = ['cgi', 'unknown'];
    public const CWE = 'CWE-88';
    public const DESCRIPTION = 'cgi.force_redirect = 0 lets php-cgi be invoked directly, the precondition for '
        . 'argument injection such as CVE-2012-1823 and CVE-2024-4577.';
    public const RECOMMENDATION = 'Keep cgi.force_redirect = 1 (only IIS needs it off), or move to PHP-FPM.';
    public const REFERENCES = [
        'https://nvd.nist.gov/vuln/detail/CVE-2012-1823',
        'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
    ];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('cgi.force_redirect');
        if ($setting->asBool()) {
            return;
        }
        if ($ctx->sapi === 'cgi') {
            yield new Hit('cgi.force_redirect is Off for php-cgi', [$setting]);
        } else {
            yield new Hit(
                'cgi.force_redirect is Off (matters if this config serves php-cgi)',
                [$setting],
                Severity::MEDIUM,
                Confidence::LOW
            );
        }
    }
}

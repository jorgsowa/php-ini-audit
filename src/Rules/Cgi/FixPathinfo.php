<?php

namespace PhpIniAudit\Rules\Cgi;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Rules\Support\PhpExtensions;
use PhpIniAudit\Severity;

final class FixPathinfo extends ConfigRule
{
    public const ID = 'CGI-002';
    public const TITLE = 'PATH_INFO fix-up executes files by path prefix';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['cgi.fix_pathinfo'];
    public const SAPIS = Sapis::FASTCGI;
    public const CWE = 'CWE-434';
    public const DESCRIPTION = 'With cgi.fix_pathinfo = 1 a request for /uploads/avatar.jpg/x.php can make PHP '
        . "execute avatar.jpg when the web server forwards any *.php path. PHP-FPM's security.limit_extensions blocks "
        . 'it.';
    public const RECOMMENDATION = 'Set cgi.fix_pathinfo = 0, or make sure the web server checks that the script '
        . 'exists (try_files $fastcgi_script_name =404) and security.limit_extensions = .php.';
    public const REFERENCES = ['https://nvd.nist.gov/vuln/detail/CVE-2019-11043'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('cgi.fix_pathinfo');
        if (!$setting->asBool()) {
            return;
        }
        if ($ctx->usesFpm()) {
            $restricted = true;
            foreach ($ctx->pools as $pool) {
                [, $exts] = PhpExtensions::allowedBy($pool);
                if ($exts !== null && (!$exts || array_diff($exts, PhpExtensions::ALL))) {
                    $restricted = false;
                    break;
                }
            }
            if ($restricted) {
                yield new Hit(
                    'cgi.fix_pathinfo = 1; mitigated by security.limit_extensions in PHP-FPM',
                    [$setting],
                    Severity::LOW
                );
                return;
            }
        }
        yield new Hit('cgi.fix_pathinfo = 1', [$setting], null, Confidence::MEDIUM);
    }
}

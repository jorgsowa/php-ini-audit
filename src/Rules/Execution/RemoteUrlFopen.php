<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class RemoteUrlFopen extends ConfigRule
{
    public const ID = 'EXEC-002';
    public const TITLE = 'Remote URLs accepted by file functions';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['allow_url_fopen'];
    public const CWE = 'CWE-918';
    public const DESCRIPTION = 'allow_url_fopen lets fopen(), file_get_contents(), getimagesize() and friends fetch '
        . 'http:// and ftp:// URLs, which turns user-controlled paths into server-side request forgery.';
    public const RECOMMENDATION = 'Set allow_url_fopen = Off and use an HTTP client (cURL) with explicit allow-lists '
        . 'where remote fetches are needed.';
    public const REFERENCES = ['https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('allow_url_fopen');
        if ($setting->asBool()) {
            yield new Hit('allow_url_fopen is enabled', [$setting], $ctx->isWeb() ? Severity::MEDIUM : Severity::LOW,
                Confidence::MEDIUM);
        }
    }
}

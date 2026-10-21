<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class RemoteFileInclusion extends ConfigRule
{
    public const ID = 'EXEC-001';
    public const TITLE = 'Remote file inclusion enabled';
    public const SEVERITY = Severity::CRITICAL;
    public const DIRECTIVES = ['allow_url_include', 'allow_url_fopen'];
    public const CWE = 'CWE-98';
    public const DESCRIPTION = 'allow_url_include lets include/require load code from http://, ftp:// and data:// '
        . 'URLs, turning any file-inclusion bug into remote code execution.';
    public const RECOMMENDATION = 'Set allow_url_include = Off. The directive has been deprecated since PHP 7.4.';
    public const REFERENCES = ['https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('allow_url_include');
        if (!$setting->asBool()) {
            return;
        }
        $fopen = $ctx->get('allow_url_fopen');
        if ($fopen->asBool()) {
            yield new Hit('allow_url_include is enabled', [$setting]);
        } else {
            yield new Hit(
                'allow_url_include is enabled; allow_url_fopen = Off blocks remote wrappers today, '
                . 'but a single change re-enables remote inclusion',
                [$setting, $fopen],
                Severity::HIGH
            );
        }
    }
}

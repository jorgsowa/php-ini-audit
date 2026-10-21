<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Support\ConfiguredPaths;
use PhpIniAudit\Severity;

final class WebServedPath extends ConfigRule
{
    public const ID = 'FS-006';
    public const TITLE = 'Sensitive path inside a web-served directory';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-538';
    public const DESCRIPTION = 'Logs, sessions, uploads or caches under the document root can be downloaded, and log '
        . 'or session files that are both web-reachable and includable enable log-poisoning attacks.';
    public const RECOMMENDATION = 'Move the path outside the document root. Pass --webroot to make this check exact.';

    public function check(Context $ctx): iterable
    {
        if ($ctx->paths === null) {
            return;
        }
        foreach (ConfiguredPaths::in($ctx) as [$spec, $setting, $path]) {
            [, , $purpose, , $webroot] = $spec;
            if ($webroot === null) {
                continue;
            }
            $confidence = $ctx->paths->webrootMatch($path);
            if ($confidence !== null) {
                yield new Hit("{$setting->name} path $path appears to be web-served; $purpose", [$setting],
                    $webroot, $confidence);
            }
        }
    }
}

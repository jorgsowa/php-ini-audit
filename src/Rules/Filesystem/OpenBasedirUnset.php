<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class OpenBasedirUnset extends ConfigRule
{
    public const ID = 'FS-001';
    public const TITLE = 'open_basedir is not set';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['open_basedir'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-22';
    public const DESCRIPTION = 'Without open_basedir, a path traversal or file-inclusion bug can reach any file the '
        . 'PHP user can read (/etc/passwd, other sites, keys). PHP does not treat it as a hard security boundary, but '
        . 'it limits the impact of common bugs.';
    public const RECOMMENDATION = 'Set open_basedir to the application directory plus its temp/session/upload '
        . 'directories, each with a trailing slash.';
    public const REFERENCES = ['https://www.php.net/manual/en/ini.core.php#ini.open-basedir'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('open_basedir');
        if ($setting->text() === '') {
            yield new Hit('open_basedir is empty', [$setting], null, Confidence::MEDIUM);
        }
    }
}

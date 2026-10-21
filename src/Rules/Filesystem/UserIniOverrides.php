<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class UserIniOverrides extends ConfigRule
{
    public const ID = 'FS-008';
    public const TITLE = 'Per-directory .user.ini overrides enabled';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['user_ini.filename'];
    public const SAPIS = Sapis::FASTCGI;
    public const CWE = 'CWE-15';
    public const DESCRIPTION = 'With CGI/FastCGI, any directory may carry a .user.ini that changes PERDIR settings '
        . 'such as auto_prepend_file. An upload vulnerability then becomes persistent code execution.';
    public const RECOMMENDATION = 'Set user_ini.filename = (empty) if applications do not need per-directory settings.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('user_ini.filename');
        if ($setting->text() !== '') {
            yield new Hit('per-directory overrides read from ' . Util::repr($setting->text()), [$setting]);
        }
    }
}

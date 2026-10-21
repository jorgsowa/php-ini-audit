<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class CurrentDirectoryInIncludePath extends ConfigRule
{
    public const ID = 'EXEC-016';
    public const TITLE = 'include_path contains the current directory';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['include_path'];
    public const CWE = 'CWE-427';
    public const DESCRIPTION = "A '.' entry makes relative include/require resolve against the working directory, "
        . 'which may be attacker-influenced (e.g. upload directories).';
    public const RECOMMENDATION = "Use absolute includes (__DIR__ . '/file.php') or remove '.' from include_path.";

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('include_path');
        $separator = preg_match('/(^|;)[A-Za-z]:[\\\\\/]/', $setting->text()) ? ';' : ':';
        if (in_array('.', array_map('trim', explode($separator, $setting->text())), true)) {
            yield new Hit("{$setting->describe()} includes '.'", [$setting]);
        }
    }
}

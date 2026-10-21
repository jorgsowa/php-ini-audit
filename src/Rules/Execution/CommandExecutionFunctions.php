<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class CommandExecutionFunctions extends ConfigRule
{
    public const ID = 'EXEC-005';
    public const TITLE = 'Command execution functions are available';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['disable_functions'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-78';
    public const DESCRIPTION = 'Functions that spawn processes turn code injection, deserialization gadgets and file '
        . 'uploads into full operating-system command execution.';
    public const RECOMMENDATION = 'List the functions the application does not use in disable_functions (php.ini or '
        . 'php_admin_value in the FPM pool). Composer and symfony/process need proc_open.';
    public const REFERENCES = ['https://www.php.net/manual/en/ini.core.php#ini.disable-functions'];

    public const FUNCTIONS = ['exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen', 'pcntl_exec'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('disable_functions');
        $disabled = $ctx->disabledFunctions();
        $available = array_values(array_filter(self::FUNCTIONS, static function (string $f) use ($disabled): bool {
            return !isset($disabled[$f]);
        }));
        if (!$available) {
            return;
        }
        if (count($available) === count(self::FUNCTIONS)) {
            $message = 'no command-execution function is disabled (' . self::names($available) . ')';
        } else {
            $message = 'disable_functions is partial; still callable: ' . self::names($available);
        }
        yield new Hit($message, [$setting], null, Confidence::MEDIUM);
    }
}

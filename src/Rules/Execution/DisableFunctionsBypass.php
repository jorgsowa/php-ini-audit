<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class DisableFunctionsBypass extends ConfigRule
{
    public const ID = 'EXEC-006';
    public const TITLE = 'disable_functions can be bypassed';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['disable_functions'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-693';
    public const DESCRIPTION = 'With every exec-style function disabled, putenv() combined with a function that '
        . 'launches sendmail lets an attacker set LD_PRELOAD and run native code anyway.';
    public const RECOMMENDATION = 'Also disable putenv and the mail launchers that are not needed, or run PHP with a '
        . 'seccomp/AppArmor profile instead of relying on disable_functions.';
    public const REFERENCES = ['https://www.php.net/manual/en/function.putenv.php'];

    private const MAIL_LAUNCHERS = ['mail', 'mb_send_mail', 'imap_mail', 'error_log'];

    public function check(Context $ctx): iterable
    {
        $disabled = $ctx->disabledFunctions();
        foreach (CommandExecutionFunctions::FUNCTIONS as $function) {
            if (!isset($disabled[$function])) {
                return;
            }
        }
        $launchers = array_values(array_filter(self::MAIL_LAUNCHERS, static function (string $f) use ($disabled): bool {
            return !isset($disabled[$f]);
        }));
        if (!isset($disabled['putenv']) && $launchers) {
            yield new Hit(
                'putenv() and ' . self::names($launchers) . ' remain callable (LD_PRELOAD bypass)',
                [$ctx->get('disable_functions')],
                null,
                Confidence::MEDIUM
            );
        }
    }
}

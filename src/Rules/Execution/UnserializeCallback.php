<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class UnserializeCallback extends ConfigRule
{
    public const ID = 'EXEC-015';
    public const TITLE = 'Callback invoked when unserialize() meets an unknown class';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['unserialize_callback_func'];
    public const CWE = 'CWE-502';
    public const DESCRIPTION = 'unserialize_callback_func is called with attacker-chosen class names while '
        . 'unserializing untrusted data, which can trigger autoloading of unexpected files.';
    public const RECOMMENDATION = 'Leave unserialize_callback_func empty unless the callback is strictly validated.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('unserialize_callback_func');
        if ($setting->text() !== '') {
            yield new Hit($setting->describe(), [$setting]);
        }
    }
}

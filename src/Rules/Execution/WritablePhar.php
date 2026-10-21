<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class WritablePhar extends ConfigRule
{
    public const ID = 'EXEC-009';
    public const TITLE = 'Phar archives writable at runtime';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['phar.readonly'];
    public const CWE = 'CWE-502';
    public const DESCRIPTION = 'phar.readonly = Off allows scripts to create and modify Phar archives, which helps '
        . 'attackers craft polyglot files for phar:// deserialization and code execution.';
    public const RECOMMENDATION = 'Set phar.readonly = On except on build machines.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('phar.readonly');
        if (!$setting->asBool()) {
            yield new Hit('phar.readonly is Off', [$setting], $ctx->isWeb() ? Severity::MEDIUM : Severity::LOW);
        }
    }
}

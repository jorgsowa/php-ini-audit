<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class UnsignedPhar extends ConfigRule
{
    public const ID = 'EXEC-010';
    public const TITLE = 'Unsigned Phar archives accepted';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['phar.require_hash'];
    public const CWE = 'CWE-345';
    public const DESCRIPTION = 'phar.require_hash = Off lets PHP open Phar archives without a signature.';
    public const RECOMMENDATION = 'Set phar.require_hash = On.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('phar.require_hash');
        if (!$setting->asBool()) {
            yield new Hit('phar.require_hash is Off', [$setting]);
        }
    }
}

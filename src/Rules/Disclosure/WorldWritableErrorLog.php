<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

final class WorldWritableErrorLog extends ConfigRule
{
    public const ID = 'ERR-009';
    public const TITLE = 'Error log created world-writable';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['error_log_mode'];
    public const CWE = 'CWE-732';
    public const DESCRIPTION = 'error_log_mode controls the permissions of a newly created error log; a '
        . 'world-writable log can be forged or used for log poisoning.';
    public const RECOMMENDATION = 'Use error_log_mode = 0640 or stricter.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('error_log_mode');
        $mode = Values::parseOctal($setting->value);
        if ($mode !== null && ($mode & 0002)) {
            yield new Hit("{$setting->describe()} grants write access to others", [$setting]);
        }
    }
}

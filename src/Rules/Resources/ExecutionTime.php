<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class ExecutionTime extends ConfigRule
{
    public const ID = 'RES-002';
    public const TITLE = 'Unlimited or long max_execution_time';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['max_execution_time'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-400';
    public const DESCRIPTION = 'max_execution_time = 0 lets slow or stuck requests occupy workers forever.';
    public const RECOMMENDATION = 'Use 30-60 seconds for web requests (and request_terminate_timeout in FPM).';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('max_execution_time');
        $seconds = $setting->asInt();
        if ($seconds <= 0) {
            yield new Hit('max_execution_time is unlimited', [$setting]);
        } elseif ($seconds > 300) {
            yield new Hit("{$setting->describe()} seconds", [$setting], Severity::LOW);
        }
    }
}

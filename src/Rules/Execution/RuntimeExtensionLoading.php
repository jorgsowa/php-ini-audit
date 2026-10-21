<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class RuntimeExtensionLoading extends ConfigRule
{
    public const ID = 'EXEC-008';
    public const TITLE = 'Runtime extension loading (dl) enabled';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['enable_dl'];
    public const CWE = 'CWE-114';
    public const DESCRIPTION = 'enable_dl permits dl() to load shared objects at runtime. dl() is only available to '
        . 'the CLI and embed SAPIs, so the impact is limited to scripts run from the command line.';
    public const RECOMMENDATION = 'Set enable_dl = Off.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('enable_dl');
        if ($setting->asBool()) {
            yield new Hit('enable_dl is enabled', [$setting], null,
                $ctx->sapi === 'cli' ? Confidence::HIGH : Confidence::MEDIUM);
        }
    }
}

<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class ProductionAssertions extends ConfigRule
{
    public const ID = 'EXEC-014';
    public const TITLE = 'Assertions compiled and executed in production';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['zend.assertions', 'assert.active'];
    public const PRODUCTION_ONLY = true;
    public const CWE = 'CWE-489';
    public const DESCRIPTION = 'zend.assertions = 1 executes assert() calls in production. Before PHP 8.0 string '
        . 'assertions were evaluated as code.';
    public const RECOMMENDATION = 'Set zend.assertions = -1 in production.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('zend.assertions');
        if ($setting->asInt() !== 1) {
            return;
        }
        if ($ctx->versionBelow(8, 0) && $ctx->on('assert.active')) {
            yield new Hit(
                "zend.assertions = 1 with assert.active on PHP < 8.0 (string assertions are eval'd)",
                [$setting, $ctx->get('assert.active')],
                Severity::MEDIUM
            );
        } else {
            yield new Hit('zend.assertions = 1', [$setting]);
        }
    }
}

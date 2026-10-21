<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class DevelopmentConfig extends ConfigRule
{
    public const ID = 'CFG-008';
    public const TITLE = 'Development configuration used in production';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['display_errors', 'zend.assertions', 'mysqlnd.collect_memory_statistics'];
    public const PRODUCTION_ONLY = true;
    public const DESCRIPTION = 'The combination of display_errors, zend.assertions and mysqlnd memory statistics '
        . 'matches php.ini-development.';
    public const RECOMMENDATION = 'Start from php.ini-production.';

    public function check(Context $ctx): iterable
    {
        $display = $ctx->get('display_errors');
        $markers = [];
        foreach (['zend.assertions', 'mysqlnd.collect_memory_statistics'] as $name) {
            $setting = $ctx->get($name);
            if ($setting->isSet() && $setting->asInt() === 1) {
                $markers[] = $setting;
            }
        }
        if ($display->isSet() && $display->asBool() && $markers) {
            yield new Hit('settings match php.ini-development', array_merge([$display], $markers), null,
                Confidence::MEDIUM);
        }
    }
}

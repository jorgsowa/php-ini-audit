<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class SocketTimeout extends ConfigRule
{
    public const ID = 'RES-010';
    public const TITLE = 'Socket reads may block indefinitely';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['default_socket_timeout'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-400';
    public const DESCRIPTION = 'A negative or very long default_socket_timeout lets slow remote peers hold workers.';
    public const RECOMMENDATION = 'Use 60 seconds or less.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('default_socket_timeout');
        $seconds = $setting->asInt();
        if ($seconds < 0 || $seconds > 300) {
            yield new Hit($setting->describe(), [$setting]);
        }
    }
}

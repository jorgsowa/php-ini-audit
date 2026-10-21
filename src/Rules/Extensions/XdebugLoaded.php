<?php

namespace PhpIniAudit\Rules\Extensions;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class XdebugLoaded extends ConfigRule
{
    public const ID = 'EXT-002';
    public const TITLE = 'Xdebug loaded';
    public const SEVERITY = Severity::HIGH;
    public const DEV_SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['zend_extension', 'xdebug.mode'];
    public const CWE = 'CWE-489';
    public const DESCRIPTION = 'Xdebug in production slows every request and, depending on xdebug.mode, exposes '
        . 'debugging, tracing and profiling output.';
    public const RECOMMENDATION = 'Do not install Xdebug on production systems.';

    public function check(Context $ctx): iterable
    {
        $directive = $ctx->loadedExtension('xdebug');
        if ($directive === null) {
            return;
        }
        $mode = $ctx->get('xdebug.mode');
        if (strtolower($mode->text()) === 'off') {
            yield new Hit('Xdebug is loaded with xdebug.mode = off', [$directive, $mode], Severity::LOW);
        } else {
            yield new Hit("Xdebug is loaded ({$mode->describe()})", [$directive, $mode]);
        }
    }
}

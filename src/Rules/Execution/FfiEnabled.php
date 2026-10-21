<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class FfiEnabled extends ConfigRule
{
    public const ID = 'EXEC-007';
    public const TITLE = 'FFI available to every script';
    public const SEVERITY = Severity::HIGH;
    public const DIRECTIVES = ['ffi.enable'];
    public const CWE = 'CWE-749';
    public const DESCRIPTION = 'ffi.enable = On lets any script call arbitrary C functions, which bypasses '
        . 'disable_functions, open_basedir and every other PHP-level restriction.';
    public const RECOMMENDATION = 'Use ffi.enable = preload (the default) so that only preloaded code can use FFI.';
    public const REFERENCES = ['https://www.php.net/manual/en/ffi.configuration.php'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('ffi.enable');
        if (strtolower($setting->text()) !== 'preload' && $setting->asBool()) {
            yield new Hit('ffi.enable allows FFI from any script', [$setting], null, Confidence::MEDIUM);
        }
    }
}

<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class StreamWrapperAutoPrepend extends ConfigRule
{
    public const ID = 'EXEC-003';
    public const TITLE = 'Auto-prepended/appended file loaded through a stream wrapper';
    public const SEVERITY = Severity::CRITICAL;
    public const DIRECTIVES = ['auto_prepend_file', 'auto_append_file'];
    public const CWE = 'CWE-94';
    public const DESCRIPTION = 'auto_prepend_file/auto_append_file pointing at php://input, data:, http:// or another '
        . 'wrapper executes request- or network-supplied code on every request; this is a classic FastCGI '
        . 'exploitation payload.';
    public const RECOMMENDATION = 'Remove the directive or point it at a root-owned local file.';

    public const STREAM_WRAPPER = '/^\s*(?:([a-z][a-z0-9+.\-]*):\/\/|data:)/i';

    public function check(Context $ctx): iterable
    {
        foreach (['auto_prepend_file', 'auto_append_file'] as $name) {
            $setting = $ctx->get($name);
            if (preg_match(self::STREAM_WRAPPER, $setting->text(), $match)
                && strtolower($match[1] ?? '') !== 'file') {
                yield new Hit("{$setting->describe()} loads code through a stream wrapper", [$setting]);
            }
        }
    }
}

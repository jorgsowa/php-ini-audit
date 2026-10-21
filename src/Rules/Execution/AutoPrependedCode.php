<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Confidence;
use PhpIniAudit\Paths;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Setting;
use PhpIniAudit\Severity;
use PhpIniAudit\SourceKind;

final class AutoPrependedCode extends ConfigRule
{
    public const ID = 'EXEC-004';
    public const TITLE = 'Code automatically prepended or appended to every script';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['auto_prepend_file', 'auto_append_file'];
    public const CWE = 'CWE-506';
    public const DESCRIPTION = 'auto_prepend_file/auto_append_file run a file before/after every script. Security '
        . 'plugins use it legitimately, but a value set from .user.ini or .htaccess is a common web-shell persistence '
        . 'technique.';
    public const RECOMMENDATION = 'Confirm the file is expected, root-owned and not writable by the PHP user; set '
        . 'user_ini.filename = to stop per-directory overrides if they are not needed.';

    public function check(Context $ctx): iterable
    {
        foreach (['auto_prepend_file', 'auto_append_file'] as $name) {
            $setting = $ctx->get($name);
            $value = $setting->text();
            if ($value === '' || strtolower($value) === 'none'
                || preg_match(StreamWrapperAutoPrepend::STREAM_WRAPPER, $value)) {
                continue;
            }
            if (self::fromOverlay($setting)) {
                yield new Hit(
                    "{$setting->describe()} is set from a per-directory file ({$setting->directive->kind})",
                    [$setting],
                    Severity::MEDIUM,
                    Confidence::LOW
                );
            } elseif (!Paths::isAbsolute($value)) {
                yield new Hit(
                    "{$setting->describe()} is a relative path resolved through include_path and the working "
                    . 'directory',
                    [$setting],
                    Severity::LOW
                );
            } else {
                yield new Hit("{$setting->describe()} runs for every request", [$setting]);
            }
        }
    }

    private static function fromOverlay(Setting $setting): bool
    {
        return $setting->directive !== null
            && in_array($setting->directive->kind, [SourceKind::USER_INI, SourceKind::HTACCESS], true);
    }
}

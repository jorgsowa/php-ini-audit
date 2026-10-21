<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

final class OpenBasedirWholeFilesystem extends ConfigRule
{
    public const ID = 'FS-002';
    public const TITLE = 'open_basedir allows the whole filesystem';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['open_basedir'];
    public const CWE = 'CWE-22';
    public const DESCRIPTION = "An open_basedir entry of '/' (or a bare drive) disables the restriction entirely.";
    public const RECOMMENDATION = 'List only the directories the application needs.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('open_basedir');
        $broad = array_values(array_filter(Values::splitPathList($setting->text()), static function (string $e): bool {
            return in_array($e, ['/', '\\'], true) || preg_match('/^[A-Za-z]:[\\\\\/]?\z/', $e);
        }));
        if ($broad) {
            yield new Hit('open_basedir contains ' . self::names($broad), [$setting]);
        }
    }
}

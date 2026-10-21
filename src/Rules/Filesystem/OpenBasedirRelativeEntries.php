<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Paths;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

final class OpenBasedirRelativeEntries extends ConfigRule
{
    public const ID = 'FS-004';
    public const TITLE = 'open_basedir uses relative entries';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['open_basedir'];
    public const CWE = 'CWE-22';
    public const DESCRIPTION = "Relative entries such as '.' are resolved against the current working directory, "
        . 'which changes with chdir() and the requested script.';
    public const RECOMMENDATION = 'Use absolute directories only.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('open_basedir');
        $relative = array_values(array_filter(Values::splitPathList($setting->text()), static function (string $e): bool {
            return !Paths::isAbsolute($e);
        }));
        if ($relative) {
            yield new Hit('relative entries: ' . self::names($relative), [$setting]);
        }
    }
}

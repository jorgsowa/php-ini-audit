<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Paths;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;
use PhpIniAudit\Values;

final class OpenBasedirPrefixMatch extends ConfigRule
{
    public const ID = 'FS-003';
    public const TITLE = 'open_basedir entries match by prefix';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['open_basedir'];
    public const CWE = 'CWE-22';
    public const DESCRIPTION = "open_basedir compares prefixes: '/var/www/site' also allows '/var/www/site-backup'. A "
        . 'trailing separator restricts the entry to that directory.';
    public const RECOMMENDATION = "End every directory entry with '/' (or '\\' on Windows).";

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('open_basedir');
        $loose = array_values(array_filter(Values::splitPathList($setting->text()), static function (string $e): bool {
            return Paths::isAbsolute($e) && !Util::endsWith($e, '/') && !Util::endsWith($e, '\\')
                && !in_array($e, ['/', '\\'], true);
        }));
        if ($loose) {
            yield new Hit('entries without trailing separator: ' . self::names($loose), [$setting]);
        }
    }
}

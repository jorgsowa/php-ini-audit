<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Confidence;
use PhpIniAudit\Directives;
use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\FileRule;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class ObsoleteDirective extends FileRule
{
    public const ID = 'CFG-002';
    public const TITLE = 'Obsolete directive';
    public const SEVERITY = Severity::INFO;
    public const DESCRIPTION = 'Directives removed from PHP are ignored. Settings such as safe_mode or '
        . 'magic_quotes_gpc give a false sense of protection; register_globals = On is critical on the old versions '
        . 'that still honour it.';
    public const RECOMMENDATION = 'Remove obsolete directives and use their modern replacements.';

    private const LEGACY_PROTECTIONS = ['safe_mode', 'magic_quotes_gpc', 'sql.safe_mode'];
    private const LEGACY_DANGERS = ['register_globals'];

    public function check(FileContext $fctx): iterable
    {
        $version = $fctx->phpVersion;
        foreach ($fctx->file->phpDirectives() as $directive) {
            $removed = Directives::removedIn($directive->name);
            if ($removed === null) {
                continue;
            }
            $removedVersion = Directives::versionTuple($removed);
            $stillActive = $version !== null && Util::compare($version, $removedVersion) < 0;
            $dangerOn = in_array($directive->name, self::LEGACY_DANGERS, true) && self::isLegacyOn($directive->value);
            if ($stillActive) {
                if ($dangerOn) {
                    yield new Hit("{$directive->name} = On on PHP {$version[0]}.{$version[1]}", [$directive],
                        Severity::CRITICAL);
                }
                continue;
            }
            if ($dangerOn) {
                yield new Hit(
                    "{$directive->name} is set On; ignored since PHP $removed but critical on older versions",
                    [$directive],
                    $version ? Severity::INFO : Severity::HIGH,
                    $version ? Confidence::HIGH : Confidence::LOW
                );
            } elseif (in_array($directive->name, self::LEGACY_PROTECTIONS, true)
                && self::isLegacyOn($directive->value)) {
                yield new Hit("{$directive->name} was removed in PHP $removed; it no longer protects anything",
                    [$directive], Severity::LOW);
            } else {
                yield new Hit("{$directive->name} was removed in PHP $removed and is ignored", [$directive]);
            }
        }
    }

    private static function isLegacyOn(string $value): bool
    {
        return $value !== '' && $value !== '0';
    }
}

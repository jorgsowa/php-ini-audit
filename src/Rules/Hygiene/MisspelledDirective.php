<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Confidence;
use PhpIniAudit\Directives;
use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\FileRule;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Rules\Support\ClosestMatch;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class MisspelledDirective extends FileRule
{
    public const ID = 'CFG-003';
    public const TITLE = 'Unknown directive resembling a known one';
    public const SEVERITY = Severity::LOW;
    public const DESCRIPTION = 'PHP ignores unknown directive names (and names are case-sensitive), so a typo such as '
        . "'display_error' leaves the intended protection unset.";
    public const RECOMMENDATION = 'Correct the directive name.';

    /** @var list<string>|null */
    private static ?array $knownNames = null;
    /** @var array<string, string> */
    private static array $knownLower = [];
    /** @var array<string, true> */
    private static array $knownPrefixes = [];

    public function check(FileContext $fctx): iterable
    {
        $sensitive = Registry::securityDirectives();
        $known = self::knownNames();
        foreach ($fctx->file->phpDirectives() as $directive) {
            $name = $directive->name;
            if (Directives::isKnown($name) || Directives::removedIn($name) !== null) {
                continue;
            }
            $suggestion = self::$knownLower[strtolower($name)] ?? null;
            if ($suggestion === null) {
                $prefix = strpos($name, '.') !== false ? explode('.', $name, 2)[0] : null;
                if ($prefix !== null && !isset(self::$knownPrefixes[$prefix])) {
                    continue;
                }
                $suggestion = ClosestMatch::find($name, $known, 0.9);
            }
            if ($suggestion !== null) {
                yield new Hit(
                    'unknown directive ' . Util::repr($name) . '; did you mean ' . Util::repr($suggestion) . '?',
                    [$directive],
                    in_array($suggestion, $sensitive, true) ? Severity::MEDIUM : Severity::LOW,
                    Confidence::MEDIUM
                );
            }
        }
    }

    /** @return list<string> sorted names of known and obsolete directives */
    private static function knownNames(): array
    {
        if (self::$knownNames === null) {
            $names = array_map('strval', array_keys(Directives::KNOWN + Directives::OBSOLETE));
            sort($names, SORT_STRING);
            self::$knownNames = $names;
            foreach ($names as $name) {
                self::$knownLower[strtolower($name)] = $name;
                if (strpos($name, '.') !== false) {
                    self::$knownPrefixes[explode('.', $name, 2)[0]] = true;
                }
            }
        }
        return self::$knownNames;
    }
}

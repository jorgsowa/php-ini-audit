<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Severity;

final class RedefinedDirective extends ConfigRule
{
    public const ID = 'CFG-004';
    public const TITLE = 'Directive redefined with a different value';
    public const SEVERITY = Severity::INFO;
    public const DESCRIPTION = 'When php.ini, scan-dir files and pool settings disagree, the last one read wins. '
        . 'Reviewers looking at only one file get the wrong picture.';
    public const RECOMMENDATION = 'Keep each security directive in one place.';

    public function check(Context $ctx): iterable
    {
        $sensitive = Registry::securityDirectives();
        $history = $ctx->config->history;
        $names = array_map('strval', array_keys($history));
        sort($names, SORT_STRING);
        foreach ($names as $name) {
            $entries = $history[$name];
            if (count($entries) < 2 || !in_array($name, $sensitive, true)) {
                continue;
            }
            $distinct = array_unique(array_map(static function ($d): string {
                return $d->value;
            }, $entries));
            if (count($distinct) < 2) {
                continue;
            }
            $final = $entries[count($entries) - 1];
            $earlier = implode(', ', array_map(static function ($d): string {
                return self::orEmpty($d->value) . " at {$d->location}";
            }, array_slice($entries, 0, -1)));
            yield new Hit("$name = " . self::orEmpty($final->value) . " overrides $earlier", [$ctx->get($name)]);
        }
    }

    private static function orEmpty(string $value): string
    {
        return $value === '' ? '(empty)' : $value;
    }
}

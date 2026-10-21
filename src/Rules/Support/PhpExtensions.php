<?php

namespace PhpIniAudit\Rules\Support;

use PhpIniAudit\Directive;
use PhpIniAudit\FpmPool;
use PhpIniAudit\Values;

/** File extensions that legitimately map to PHP, and the ones a pool allows. */
final class PhpExtensions
{
    public const ALL = ['.php', '.php3', '.php4', '.php5', '.php7', '.php8', '.phtml', '.phar'];

    public static function isPhp(string $extension): bool
    {
        return in_array($extension, self::ALL, true);
    }

    /** @return array{?Directive, ?list<string>} security.limit_extensions and its lower-cased entries */
    public static function allowedBy(FpmPool $pool): array
    {
        $directive = $pool->settings['security.limit_extensions'] ?? null;
        if ($directive === null) {
            return [null, null];
        }
        return [$directive, array_map('strtolower', Values::splitList($directive->value))];
    }
}

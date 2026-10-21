<?php

namespace PhpIniAudit;

final class Severity
{
    public const INFO = 0;
    public const LOW = 1;
    public const MEDIUM = 2;
    public const HIGH = 3;
    public const CRITICAL = 4;

    public const NAMES = [self::INFO => 'info', self::LOW => 'low', self::MEDIUM => 'medium', self::HIGH => 'high',
        self::CRITICAL => 'critical'];

    public static function parse(string $text): int
    {
        $severity = array_search(strtolower(trim($text)), self::NAMES, true);
        if ($severity === false) {
            throw new \InvalidArgumentException(sprintf("unknown severity: '%s'", $text));
        }
        return $severity;
    }

    public static function name(int $severity): string
    {
        return self::NAMES[$severity];
    }
}

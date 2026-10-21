<?php

namespace PhpIniAudit;

final class Confidence
{
    public const LOW = 0;
    public const MEDIUM = 1;
    public const HIGH = 2;

    public const NAMES = [self::LOW => 'low', self::MEDIUM => 'medium', self::HIGH => 'high'];

    public static function name(int $confidence): string
    {
        return self::NAMES[$confidence];
    }
}

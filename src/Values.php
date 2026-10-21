<?php

namespace PhpIniAudit;

/** Interpretation of INI values the way PHP's own parsers read them. */
final class Values
{
    public const ERROR_CONSTANTS = [
        'E_ERROR' => 1,
        'E_WARNING' => 2,
        'E_PARSE' => 4,
        'E_NOTICE' => 8,
        'E_CORE_ERROR' => 16,
        'E_CORE_WARNING' => 32,
        'E_COMPILE_ERROR' => 64,
        'E_COMPILE_WARNING' => 128,
        'E_USER_ERROR' => 256,
        'E_USER_WARNING' => 512,
        'E_USER_NOTICE' => 1024,
        'E_STRICT' => 2048,
        'E_RECOVERABLE_ERROR' => 4096,
        'E_DEPRECATED' => 8192,
        'E_USER_DEPRECATED' => 16384,
        'E_ALL' => 32767,
    ];

    private const MULTIPLIERS = ['' => 1, 'k' => 1024, 'm' => 1048576, 'g' => 1073741824];

    /** C atoi(): leading integer, 0 when there is none. */
    public static function atoi(?string $text): int
    {
        if (!preg_match('/^\s*([+-]?\d+)/', $text ?? '', $match)) {
            return 0;
        }
        return self::clamp((float) $match[1]);
    }

    /** zend_ini_parse_bool(). */
    public static function toBool(?string $value): bool
    {
        if ($value === null) {
            return false;
        }
        $text = strtolower(trim($value));
        if (in_array($text, ['on', 'yes', 'true'], true)) {
            return true;
        }
        return self::atoi($text) !== 0;
    }

    /** zend_ini_parse_quantity(); null when the value is not a valid quantity. */
    public static function toBytes(?string $value): ?int
    {
        if ($value === null) {
            return null;
        }
        if (!preg_match('/^\s*([+-]?)(0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|\d+)\s*([kKmMgG]?)\s*$/D', $value, $match)) {
            return null;
        }
        [, $sign, $digits, $suffix] = $match;
        $prefix = strtolower(substr($digits, 0, 2));
        if ($prefix === '0x') {
            $number = hexdec(substr($digits, 2));
        } elseif ($prefix === '0o') {
            $number = octdec(substr($digits, 2));
        } elseif ($prefix === '0b') {
            $number = bindec(substr($digits, 2));
        } else {
            $number = (float) $digits;
        }
        $number *= self::MULTIPLIERS[strtolower($suffix)];
        return self::clamp($sign === '-' ? -$number : $number);
    }

    /** Comma/whitespace separated lists such as disable_functions. */
    public static function splitList(?string $value): array
    {
        if ($value === null || $value === '') {
            return [];
        }
        return array_values(array_filter(preg_split('/[,\s]+/', $value), 'strlen'));
    }

    /** Split on runs of whitespace, dropping empty items. */
    public static function splitWhitespace(string $text): array
    {
        return preg_split('/[\s\x1c-\x1f]+/', $text, -1, PREG_SPLIT_NO_EMPTY);
    }

    /** Path lists such as include_path and open_basedir: ";" on Windows, ":" elsewhere. */
    public static function splitPathList(string $value): array
    {
        $separator = preg_match('/(^|;)[A-Za-z]:[\\\\\/]/', $value) ? ';' : ':';
        $entries = [];
        foreach (explode($separator, $value) as $entry) {
            if (trim($entry) !== '') {
                $entries[] = trim($entry);
            }
        }
        return $entries;
    }

    /** session.save_path accepts "N;MODE;/path"; the directory is the last segment. */
    public static function sessionDir(string $value): string
    {
        $separator = strrpos($value, ';');
        return trim($separator === false ? $value : substr($value, $separator + 1));
    }

    public static function parseOctal(?string $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        $text = trim($value);
        if (!preg_match('/^0?[0-7]{3,4}$/D', $text)) {
            return null;
        }
        return (int) octdec($text);
    }

    /**
     * Evaluate an error_reporting expression without eval().
     * The INI grammar gives |, & and ^ equal precedence with left associativity.
     */
    public static function evalErrorReporting(?string $expression): ?int
    {
        if ($expression === null) {
            return null;
        }
        preg_match_all('/\s*(?:(\d+)|([A-Za-z_][A-Za-z0-9_]*)|(\S))/', $expression, $matches, PREG_SET_ORDER);
        $tokens = [];
        foreach ($matches as $match) {
            if (($match[1] ?? '') !== '') {
                $tokens[] = ['num', self::clamp((float) $match[1])];
            } elseif (($match[2] ?? '') !== '') {
                if (!isset(self::ERROR_CONSTANTS[$match[2]])) {
                    return null;
                }
                $tokens[] = ['num', self::ERROR_CONSTANTS[$match[2]]];
            } elseif (($match[3] ?? '') !== '') {
                $tokens[] = ['op', $match[3]];
            }
        }
        if (!$tokens) {
            return null;
        }
        $position = 0;
        $peek = static function () use (&$tokens, &$position): array {
            return $tokens[$position] ?? [null, null];
        };
        $binary = null;
        $unary = static function () use (&$unary, &$binary, $peek, &$position): int {
            [$kind, $token] = $peek();
            if ($kind === 'op' && ($token === '~' || $token === '!')) {
                $position++;
                $operand = $unary();
                return $token === '~' ? ~$operand : (int) !$operand;
            }
            if ($kind === 'op' && $token === '(') {
                $position++;
                $result = $binary();
                if ($peek() !== ['op', ')']) {
                    throw new \InvalidArgumentException('unbalanced parentheses');
                }
                $position++;
                return $result;
            }
            if ($kind === 'num') {
                $position++;
                return $token;
            }
            throw new \InvalidArgumentException('unexpected token');
        };
        $binary = static function () use ($unary, $peek, &$position): int {
            $result = $unary();
            while (true) {
                [$kind, $token] = $peek();
                if ($kind !== 'op' || !in_array($token, ['|', '&', '^'], true)) {
                    return $result;
                }
                $position++;
                $right = $unary();
                if ($token === '|') {
                    $result |= $right;
                } elseif ($token === '&') {
                    $result &= $right;
                } else {
                    $result ^= $right;
                }
            }
        };
        try {
            $value = $binary();
        } catch (\InvalidArgumentException $exception) {
            return null;
        }
        return $position === count($tokens) ? $value : null;
    }

    /** @param int|float $number */
    private static function clamp($number): int
    {
        if ($number >= PHP_INT_MAX) {
            return PHP_INT_MAX;
        }
        if ($number <= PHP_INT_MIN) {
            return PHP_INT_MIN;
        }
        return (int) $number;
    }
}

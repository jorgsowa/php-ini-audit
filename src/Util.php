<?php

namespace PhpIniAudit;

final class Util
{
    /** Stable sort (PHP 7.4's sort functions are not stable). */
    public static function sort(array $items, callable $compare): array
    {
        $indexed = [];
        foreach (array_values($items) as $index => $item) {
            $indexed[] = [$index, $item];
        }
        usort($indexed, static function (array $a, array $b) use ($compare): int {
            return $compare($a[1], $b[1]) ?: $a[0] <=> $b[0];
        });
        return array_column($indexed, 1);
    }

    /** Stable sort by a key; keys compare with compare(). */
    public static function sortBy(array $items, callable $key): array
    {
        $keyed = [];
        foreach (array_values($items) as $index => $item) {
            $keyed[] = [$key($item), $index, $item];
        }
        usort($keyed, static function (array $a, array $b): int {
            return self::compare($a[0], $b[0]) ?: $a[1] <=> $b[1];
        });
        return array_column($keyed, 2);
    }

    /** Lexicographic comparison of lists (PHP's own array comparison orders by length first). */
    public static function compare($a, $b): int
    {
        if (!is_array($a) || !is_array($b)) {
            return $a <=> $b;
        }
        $a = array_values($a);
        $b = array_values($b);
        $length = min(count($a), count($b));
        for ($i = 0; $i < $length; $i++) {
            $order = self::compare($a[$i], $b[$i]);
            if ($order !== 0) {
                return $order;
            }
        }
        return count($a) <=> count($b);
    }

    /** Split on every line break a configuration file may use; a trailing break adds no empty line. */
    public static function splitLines(string $text): array
    {
        if ($text === '') {
            return [];
        }
        $lines = preg_split('/\r\n|[\r\n\x0b\x0c\x1c\x1d\x1e]/', $text);
        if (end($lines) === '') {
            array_pop($lines);
        }
        return $lines;
    }

    public static function startsWith(string $haystack, string $needle): bool
    {
        return strncmp($haystack, $needle, strlen($needle)) === 0;
    }

    public static function endsWith(string $haystack, string $needle): bool
    {
        return $needle === '' || substr($haystack, -strlen($needle)) === $needle;
    }

    public static function contains(string $haystack, string $needle): bool
    {
        return strpos($haystack, $needle) !== false;
    }

    /** Quote a string for messages, escaping control characters. */
    public static function repr(string $text): string
    {
        $quote = strpos($text, "'") !== false && strpos($text, '"') === false ? '"' : "'";
        $escaped = preg_replace_callback('/[\\\\\x00-\x1f\x7f]|' . $quote . '/', static function (array $m) use ($quote): string {
            $map = ["\\" => '\\\\', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t', $quote => '\\' . $quote];
            return $map[$m[0]] ?? sprintf('\\x%02x', ord($m[0]));
        }, $text);
        return $quote . $escaped . $quote;
    }

    /** First $length characters of a UTF-8 string. */
    public static function head(string $text, int $length): string
    {
        return preg_match('/^.{0,' . $length . '}/su', $text, $match) ? $match[0] : substr($text, 0, $length);
    }
}

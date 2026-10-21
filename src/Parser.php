<?php

namespace PhpIniAudit;

/** Parsers for php.ini-style files, php-fpm configs and .htaccess PHP directives; nothing is expanded or executed. */
final class Parser
{
    public const BOOL_WORDS = [
        'on' => '1',
        'yes' => '1',
        'true' => '1',
        'off' => '',
        'no' => '',
        'false' => '',
        'none' => '',
        'null' => '',
    ];
    private const CONDITIONAL_SECTION = '/^(PATH|HOST)\s*=/i';
    private const FPM_PHP_KEY = '/^(php_value|php_flag|php_admin_value|php_admin_flag)\[(.+)\]$/sD';
    private const FPM_ENV_KEY = '/^env\[(.+)\]$/sD';
    private const MAX_CONTINUATION_LINES = 100;
    private const HTACCESS_PHP = ['php_value', 'php_flag', 'php_admin_value', 'php_admin_flag'];
    private const FILES_OPEN = '/^<\s*(FilesMatch|Files)\s+(.+?)\s*>$/iD';
    private const FILES_CLOSE = '/^<\/\s*(FilesMatch|Files)\s*>$/iD';

    public static function isConditional(?string $section): bool
    {
        return $section !== null && $section !== '' && preg_match(self::CONDITIONAL_SECTION, $section) === 1;
    }

    /** @return array{string, bool, bool} value, has_env_reference, unterminated_quote for the right-hand side of '=' */
    public static function scanValue(string $text): array
    {
        $parts = [];
        $unresolved = false;
        $i = 0;
        $n = strlen($text);
        while ($i < $n) {
            $char = $text[$i];
            if ($char === ';') {
                break;
            }
            if ($char === '"') {
                $j = $i + 1;
                $buf = '';
                while ($j < $n && $text[$j] !== '"') {
                    if ($text[$j] === '\\' && $j + 1 < $n && strpos('"\\$', $text[$j + 1]) !== false) {
                        $buf .= $text[$j + 1];
                        $j += 2;
                        continue;
                    }
                    $buf .= $text[$j];
                    $j++;
                }
                if ($j >= $n) {
                    return ['', $unresolved, true];
                }
                $unresolved = $unresolved || Util::contains($buf, '${');
                $parts[] = ['quoted', $buf];
                $i = $j + 1;
                continue;
            }
            if ($char === "'") {
                $j = strpos($text, "'", $i + 1);
                if ($j === false) {
                    return ['', $unresolved, true];
                }
                $parts[] = ['quoted', substr($text, $i + 1, $j - $i - 1)];
                $i = $j + 1;
                continue;
            }
            $j = $i + strcspn($text, ";\"'", $i);
            $chunk = substr($text, $i, $j - $i);
            $unresolved = $unresolved || Util::contains($chunk, '${');
            $parts[] = ['bare', $chunk];
            $i = $j;
        }

        $hasQuotes = false;
        foreach ($parts as [$kind]) {
            $hasQuotes = $hasQuotes || $kind === 'quoted';
        }
        $value = '';
        foreach ($parts as [$kind, $chunk]) {
            $value .= $kind === 'bare' && $hasQuotes ? trim($chunk) : $chunk;
        }
        if (!$hasQuotes) {
            $value = trim($value);
        }
        if (count($parts) === 1 && $parts[0][0] === 'bare') {
            $value = self::BOOL_WORDS[strtolower($value)] ?? $value;
        }
        return [$value, $unresolved, false];
    }

    public static function parseIni(string $text, string $path, string $kind): IniFile
    {
        $result = new IniFile($path, $kind);
        $lines = Util::splitLines($text);
        $section = null;
        $index = 0;
        $count = count($lines);
        while ($index < $count) {
            $lineno = $index + 1;
            $stripped = trim($lines[$index]);
            $index++;
            $location = new Location($path, $lineno);
            if ($stripped === '' || $stripped[0] === ';') {
                continue;
            }
            if ($stripped[0] === '#') {
                $result->issues[] = new ParseIssue($location,
                    "'#' is not a comment since PHP 7.0; use ';' (the line may abort INI parsing)");
                continue;
            }
            if ($stripped[0] === '[') {
                $end = strpos($stripped, ']');
                if ($end === false) {
                    $result->issues[] = new ParseIssue($location, 'unterminated section header');
                    continue;
                }
                $section = trim(substr($stripped, 1, $end - 1));
                if (self::isConditional($section)) {
                    $result->conditionalSections[] = [$section, $location];
                }
                continue;
            }
            if (!Util::contains($stripped, '=')) {
                $result->issues[] = new ParseIssue($location,
                    "line without '=' is a syntax error: " . Util::repr(Util::head($stripped, 60)));
                continue;
            }
            [$key, $rest] = explode('=', $stripped, 2);
            $key = trim($key);
            if ($key === '') {
                $result->issues[] = new ParseIssue($location, 'assignment without a directive name');
                continue;
            }
            [$value, $unresolved, $unterminated] = self::scanValue($rest);
            $extra = 0;
            while ($unterminated && $index < $count && $extra < self::MAX_CONTINUATION_LINES) {
                $rest .= "\n" . $lines[$index];
                $index++;
                $extra++;
                [$value, $unresolved, $unterminated] = self::scanValue($rest);
            }
            if ($unterminated) {
                $result->issues[] = new ParseIssue($location, "unterminated quoted value for $key");
                continue;
            }
            $result->directives[] = new Directive($key, $value, trim($rest), $location, $kind, $section, false,
                $unresolved);
        }
        return $result;
    }

    /** php-fpm.conf / pool.d files share the INI grammar; sections name the pools. */
    public static function parseFpm(string $text, string $path): FpmFile
    {
        $ini = self::parseIni($text, $path, SourceKind::FPM);
        $result = new FpmFile($path);
        $result->issues = $ini->issues;
        $pools = [];
        foreach ($ini->directives as $directive) {
            $section = $directive->section ?? 'global';
            if ($section === '') {
                $section = 'global';
            }
            if (strtolower($section) === 'global') {
                $result->globalSettings[$directive->name] = $directive;
                continue;
            }
            $pool = $pools[$section] ?? null;
            if ($pool === null) {
                $pool = new FpmPool($section, new Location($path, $directive->location->line));
                $pools[$section] = $pool;
                $result->pools[] = $pool;
            }
            if (preg_match(self::FPM_PHP_KEY, $directive->name, $php)) {
                $pool->php[] = new Directive(trim($php[2]), $directive->value, $directive->raw, $directive->location,
                    SourceKind::FPM, $section, Util::startsWith($php[1], 'php_admin'), $directive->unresolved);
            } elseif (preg_match(self::FPM_ENV_KEY, $directive->name, $env)) {
                $pool->env[] = new Directive(trim($env[1]), $directive->value, $directive->raw, $directive->location,
                    SourceKind::FPM, $section);
            } else {
                $pool->settings[$directive->name] = $directive;
            }
        }
        return $result;
    }

    public static function parseHtaccess(string $text, string $path): HtaccessFile
    {
        $result = new HtaccessFile($path);
        $filesStack = [];
        foreach (Util::splitLines($text) as $index => $line) {
            $stripped = trim($line);
            $location = new Location($path, $index + 1);
            if ($stripped === '' || $stripped[0] === '#') {
                continue;
            }
            if (preg_match(self::FILES_OPEN, $stripped, $opening)) {
                $filesStack[] = trim(trim($opening[2]), "\"'");
                continue;
            }
            if (preg_match(self::FILES_CLOSE, $stripped)) {
                array_pop($filesStack);
                continue;
            }
            $tokens = self::shellSplit($stripped);
            if ($tokens === null) {
                $tokens = preg_split('/\s+/', $stripped, -1, PREG_SPLIT_NO_EMPTY);
            }
            if (!$tokens) {
                continue;
            }
            $keyword = strtolower($tokens[0]);
            $pattern = $filesStack ? end($filesStack) : null;
            if (in_array($keyword, self::HTACCESS_PHP, true)) {
                if (Util::startsWith($keyword, 'php_admin')) {
                    $result->issues[] = new ParseIssue($location,
                        "{$tokens[0]} is not allowed in .htaccess (Apache answers 500)");
                    continue;
                }
                if (count($tokens) < 2) {
                    $result->issues[] = new ParseIssue($location, "{$tokens[0]} without a directive name");
                    continue;
                }
                $raw = implode(' ', array_slice($tokens, 2));
                $value = $raw;
                if ($keyword === 'php_flag' || in_array(strtolower($raw), ['none', ''], true)) {
                    $value = self::BOOL_WORDS[strtolower($raw)] ?? $raw;
                }
                $result->directives[] = new Directive($tokens[1], $value, $raw, $location, SourceKind::HTACCESS, null,
                    false, Util::contains($raw, '${'));
            } elseif (in_array($keyword, ['addtype', 'addhandler'], true) && count($tokens) >= 3
                && Util::contains(strtolower($tokens[1]), 'php')) {
                $result->handlers[] = new HandlerMapping($location, $stripped,
                    array_map('strtolower', array_slice($tokens, 2)), $pattern);
            } elseif ($keyword === 'sethandler' && count($tokens) >= 2 && Util::contains(strtolower($tokens[1]), 'php')) {
                $result->handlers[] = new HandlerMapping($location, $stripped, [], $pattern);
            }
        }
        return $result;
    }

    /** Split words like a POSIX shell; null on an unclosed quote or a trailing backslash. */
    public static function shellSplit(string $text): ?array
    {
        $tokens = [];
        $token = null;
        $quote = null;
        $n = strlen($text);
        for ($i = 0; $i < $n; $i++) {
            $char = $text[$i];
            if ($quote === "'") {
                if ($char === "'") {
                    $quote = null;
                } else {
                    $token .= $char;
                }
            } elseif ($quote === '"') {
                if ($char === '"') {
                    $quote = null;
                } elseif ($char === '\\' && $i + 1 < $n && strpos("\\\"\$`\n", $text[$i + 1]) !== false) {
                    $token .= $text[++$i];
                } elseif ($char === '\\' && $i + 1 >= $n) {
                    return null;
                } else {
                    $token .= $char;
                }
            } elseif ($char === '\\') {
                if ($i + 1 >= $n) {
                    return null;
                }
                $token .= $text[++$i];
            } elseif ($char === "'" || $char === '"') {
                $quote = $char;
                $token .= '';
            } elseif (strpos(" \t\r\n", $char) !== false) {
                if ($token !== null) {
                    $tokens[] = $token;
                    $token = null;
                }
            } else {
                $token .= $char;
            }
        }
        if ($quote !== null) {
            return null;
        }
        if ($token !== null) {
            $tokens[] = $token;
        }
        return $tokens;
    }
}

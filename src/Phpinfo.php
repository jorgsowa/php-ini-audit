<?php

namespace PhpIniAudit;

/** Audit the effective configuration shown by phpinfo(): `php -i` text, the HTML page, or text copied from it. */
final class Phpinfo
{
    public const SOURCE = 'phpinfo()';
    private const NAME = '/^[A-Za-z0-9_][A-Za-z0-9_.\-]*$/D';
    private const MODULE = '/^[A-Za-z][A-Za-z0-9_ +]*$/D';
    private const VERSION = '/^(\d+)\.(\d+)\.(\d+)(.*)$/D';
    private const HEADINGS = ['phpinfo()', 'configuration', 'additional modules', 'environment', 'php variables',
        'php credits', 'php license', 'directive', 'variable', 'credits', 'php core', 'php group',
        'language design & concept'];
    // phpinfo() prints display names ("Apache 2.0 Handler"); PHP_SAPI prints "apache2handler", "cli".
    private const SAPIS = [['fpm', 'fpm'], ['command line', 'cli'], ['apache 2', 'apache2'], ['apache2', 'apache2'],
        ['cgi', 'cgi'], ['litespeed', 'litespeed'], ['embed', 'embed'], ['cli', 'cli']];
    // Displayers that print something other than the INI value.
    private const DISPLAYED = [
        'display_errors' => ['stdout' => '1', 'stderr' => 'stderr'],
        'odbc.default_cursortype' => ['forward only cursor' => '0', 'keyset driven cursor' => '1',
            'dynamic cursor' => '2', 'static cursor' => '3'],
        'odbc.defaultbinmode' => ['passthru' => '0', 'return as is' => '1', 'return as char' => '2'],
        'odbc.defaultlrl' => ['passthru' => '0'],
    ];
    private const RETURN_BYTES = '/^return up to (\d+) bytes$/D';
    // Elements whose content HTMLParser treats as text up to the matching end tag.
    private const RAW_TEXT = ['script', 'style', 'xmp', 'iframe', 'noembed', 'noframes', 'textarea', 'title'];
    private const WHITESPACE = '\s\x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}';

    /** Trim Unicode whitespace as well as ASCII. */
    private static function strip(string $text): string
    {
        $stripped = preg_replace('/^[' . self::WHITESPACE . ']+|[' . self::WHITESPACE . ']+$/uD', '', $text);
        return $stripped ?? trim($text);
    }

    private static function rstrip(string $text): string
    {
        $stripped = preg_replace('/[' . self::WHITESPACE . ']+$/uD', '', $text);
        return $stripped ?? rtrim($text);
    }

    private static function clean(string $name, string $value): string
    {
        $value = self::strip($value);
        if ($value === 'no value') {
            return '';
        }
        if ($value === 'Unlimited') {
            return '-1';
        }
        if (preg_match(self::RETURN_BYTES, $value, $match)) {
            return $match[1];
        }
        return self::DISPLAYED[$name][strtolower($value)] ?? $value;
    }

    private static function moduleName(string $text): string
    {
        $name = strtolower(self::strip($text));
        return str_replace(' ', '_', preg_replace('/^zend\s+/', '', $name));
    }

    /** @param list<string> $cells */
    private static function addRow(PhpinfoDump $info, array $cells, int $line): void
    {
        $cells = array_map([self::class, 'strip'], $cells);
        if (count($cells) === 2 && $cells[0] !== '' && !array_key_exists($cells[0], $info->fields)) {
            $info->fields[$cells[0]] = $cells[1];
        } elseif (count($cells) === 3 && preg_match(self::NAME, $cells[0]) && $cells[0] !== 'Directive') {
            if (!array_key_exists($cells[0], $info->settings)) {
                $info->settings[$cells[0]] = [self::clean($cells[0], $cells[1]), $line];
            }
        }
    }

    private static function unescape(string $text): string
    {
        return html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /** The subset of html.parser.HTMLParser that reads phpinfo() tables. */
    private static function parseHtml(string $text, PhpinfoDump $info): void
    {
        $row = $cell = $module = $title = null;
        $rowLine = $moduleLine = 0;
        $data = static function (string $chunk) use (&$cell, &$module, &$title): void {
            foreach ([&$cell, &$module, &$title] as &$buffer) {
                if ($buffer !== null) {
                    $buffer[] = $chunk;
                }
            }
        };
        $start = static function (string $tag, array $attrs, int $line) use (&$row, &$cell, &$module, &$title,
            &$rowLine, &$moduleLine): void {
            if ($tag === 'tr') {
                [$row, $rowLine] = [[], $line];
            } elseif (($tag === 'td' || $tag === 'th') && $row !== null) {
                $cell = [];
            } elseif ($tag === 'a' && Util::startsWith((string) ($attrs['name'] ?? ''), 'module_')) {
                [$module, $moduleLine] = [[], $line];
            } elseif ($tag === 'h1') {
                $title = [];
            }
        };
        $end = static function (string $tag) use ($info, &$row, &$cell, &$module, &$title, &$rowLine,
            &$moduleLine): void {
            if (($tag === 'td' || $tag === 'th') && $cell !== null && $row !== null) {
                $row[] = implode('', $cell);
                $cell = null;
            } elseif ($tag === 'tr' && $row !== null) {
                self::addRow($info, $row, $rowLine);
                $row = null;
            } elseif ($tag === 'a' && $module !== null) {
                $info->modules[] = [self::moduleName(implode('', $module)), $moduleLine];
                $module = null;
            } elseif ($tag === 'h1' && $title !== null) {
                if (preg_match('/^PHP Version (\S+)/', self::strip(implode('', $title)), $match)
                    && !array_key_exists('PHP Version', $info->fields)) {
                    $info->fields['PHP Version'] = $match[1];
                }
                $title = null;
            }
        };

        $length = strlen($text);
        $offset = 0;
        $line = 1;
        $pending = '';
        $flush = static function () use (&$pending, $data): void {
            if ($pending !== '') {
                $data(self::unescape($pending));
                $pending = '';
            }
        };
        while ($offset < $length) {
            $next = strpos($text, '<', $offset);
            if ($next === false) {
                $pending .= substr($text, $offset);
                break;
            }
            if ($next > $offset) {
                $chunk = substr($text, $offset, $next - $offset);
                $pending .= $chunk;
                $line += substr_count($chunk, "\n");
                $offset = $next;
            }
            $tagLine = $line;
            if (preg_match('/\G<([a-zA-Z][^\t\n\r\f \/>\x00]*)((?:"[^"]*"|\'[^\']*\'|[^\'">])*)>/', $text, $m, 0, $offset)) {
                $flush();
                $tag = strtolower($m[1]);
                $attrs = [];
                preg_match_all('/([^\s\/>=][^\s\/=>]*)(?:\s*=+\s*(\'[^\']*\'|"[^"]*"|(?![\'"])[^>\s]*))?/', $m[2],
                    $pairs, PREG_SET_ORDER);
                foreach ($pairs as $pair) {
                    $value = $pair[2] ?? null;
                    if ($value !== null && $value !== '' && ($value[0] === '"' || $value[0] === "'")) {
                        $value = substr($value, 1, -1);
                    }
                    $attrs[strtolower($pair[1])] = $value === null ? null : self::unescape($value);
                }
                $offset += strlen($m[0]);
                $line += substr_count($m[0], "\n");
                $start($tag, $attrs, $tagLine);
                if (Util::endsWith(rtrim($m[2]), '/')) {
                    $end($tag);
                } elseif (in_array($tag, self::RAW_TEXT, true)) {
                    if (!preg_match('/<\/' . preg_quote($tag, '/') . '[\s\/>]/i', $text, $close, PREG_OFFSET_CAPTURE, $offset)) {
                        break;
                    }
                    $raw = substr($text, $offset, $close[0][1] - $offset);
                    $data($raw);
                    $line += substr_count($raw, "\n");
                    $offset = $close[0][1];
                }
                continue;
            }
            if (preg_match('/\G<\/([a-zA-Z][^\t\n\r\f \/>\x00]*)[^>]*>/', $text, $m, 0, $offset)) {
                $flush();
                $offset += strlen($m[0]);
                $line += substr_count($m[0], "\n");
                $end(strtolower($m[1]));
                continue;
            }
            $markup = null;
            if (substr($text, $offset, 4) === '<!--') {
                $close = strpos($text, '-->', $offset + 4);
                $markup = $close === false ? false : $close + 3;
            } elseif (preg_match('/\G<(?:[!?]|\/[^a-zA-Z])/', $text, $m, 0, $offset)) {
                $close = strpos($text, '>', $offset + 2);
                $markup = $close === false ? false : $close + 1;
            }
            if ($markup === false) {
                break;
            }
            if ($markup !== null) {
                $flush();
                $line += substr_count($text, "\n", $offset, $markup - $offset);
                $offset = $markup;
                continue;
            }
            $pending .= '<';
            $offset++;
        }
        $flush();
    }

    private static function parseText(string $text, PhpinfoDump $info): void
    {
        $lines = Util::splitLines($text);
        $index = 0;
        $count = count($lines);
        while ($index < $count) {
            $line = self::rstrip($lines[$index]);
            $number = $index + 1;
            $index++;
            if (Util::contains($line, "\t")) {
                $cells = explode("\t", $line);
            } elseif (Util::contains($line, ' => ')) {
                $cells = explode(' => ', $line);
                // `php -i` wraps long lists such as "Additional .ini files parsed" after each comma.
                while (count($cells) === 2 && Util::endsWith($cells[1], ',') && $index < $count) {
                    $cells[1] .= self::strip($lines[$index]);
                    $index++;
                }
            } else {
                $stripped = self::strip($line);
                $before = $number >= 2 ? self::strip($lines[$number - 2]) : '';
                $after = $number < $count ? self::strip($lines[$number]) : '';
                if (preg_match('/^PHP Version (\S+)$/D', $stripped, $match)) {
                    if (!array_key_exists('PHP Version', $info->fields)) {
                        $info->fields['PHP Version'] = $match[1];
                    }
                } elseif (preg_match(self::MODULE, $stripped) && $before === '' && $after === ''
                    && !in_array(strtolower($stripped), self::HEADINGS, true)) {
                    $info->modules[] = [self::moduleName($stripped), $number];
                }
                continue;
            }
            self::addRow($info, $cells, $number);
        }
    }

    public static function parse(string $text): PhpinfoDump
    {
        $info = new PhpinfoDump();
        if (preg_match('/<t[dr][\s>]/i', $text)) {
            self::parseHtml($text, $info);
        } else {
            self::parseText($text, $info);
        }
        if (!$info->settings) {
            throw new \InvalidArgumentException(
                'no phpinfo() directive table found: paste the output of phpinfo() or `php -i`');
        }
        return $info;
    }

    private static function sapi(string $serverApi): string
    {
        $lowered = strtolower($serverApi);
        foreach (self::SAPIS as [$marker, $sapi]) {
            if (Util::contains($lowered, $marker)) {
                return $sapi;
            }
        }
        return 'unknown';
    }

    /** @return array{0: list<int>|null, 1: bool} */
    private static function version(string $text): array
    {
        if (!preg_match(self::VERSION, self::strip($text), $match)) {
            return [null, false];
        }
        $suffix = strtolower($match[4]);
        // Distribution builds (8.2.7-1~deb12u1) backport fixes; deb.sury.org builds track upstream.
        $backports = preg_match('/deb|ubuntu|el\d/', $suffix) && !Util::contains($suffix, 'sury');
        return [[(int) $match[1], (int) $match[2], (int) $match[3]], $backports];
    }

    private static function same(string $value, ?string $default): bool
    {
        if ($default === null) {
            return false;
        }
        if ($value === 'On' || $value === 'Off') {
            return Values::toBool($value) === Values::toBool($default);
        }
        return $value === $default;
    }

    public static function buildTarget(PhpinfoDump $info, Options $options): Target
    {
        $layers = [];
        foreach ($info->settings as $name => [$value, $line]) {
            $name = (string) $name;
            if (self::same($value, Directives::default($name))) {
                continue;
            }
            $layers[] = new Directive($name, $value, $value, new Location(self::SOURCE, $line), SourceKind::PHPINFO);
        }
        foreach ($info->modules as [$module, $line]) {
            $layers[] = new Directive('extension', $module, $module, new Location(self::SOURCE, $line),
                SourceKind::PHPINFO);
        }
        [$version, $backports] = self::version($info->fields['PHP Version'] ?? '');
        $source = $version ? self::SOURCE : null;
        if ($options->phpVersion) {
            [$version, $source, $backports] = [$options->phpVersion, '--php-version', false];
        }
        $loaded = $info->fields['Loaded Configuration File'] ?? '';
        $files = [];
        foreach (array_merge([$loaded], explode(',', $info->fields['Additional .ini files parsed'] ?? '')) as $i => $path) {
            $path = $i === 0 ? $path : self::strip($path);
            if ($path !== '' && $path !== '(none)') {
                $files[] = $path;
            }
        }
        $sapi = $options->sapi;
        if ($sapi === null || $sapi === '') {
            $sapi = self::sapi($info->fields['Server API'] ?? '');
        }
        $target = new Target(self::SOURCE, $sapi, $version, $files, new EffectiveConfig($layers));
        $target->versionSource = $source;
        $target->versionBackports = $backports;
        $target->platform = Util::startsWith($info->fields['System'] ?? '', 'Windows') ? 'windows' : 'posix';
        $target->layers = $layers;
        $target->defaultsReason = $loaded === '(none)' ? 'phpinfo() reports no loaded php.ini' : null;
        $target->observed = array_fill_keys(array_map('strval', array_keys($info->settings)), true);
        return $target;
    }

    public static function audit(string $text, ?Options $options = null): AuditResult
    {
        $options = $options ?? new Options();
        $options->pathChecks = false;
        return (new Auditor(new FileSystem(), $options))->evaluate([self::buildTarget(self::parse($text), $options)]);
    }
}

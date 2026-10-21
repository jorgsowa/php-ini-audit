<?php

namespace PhpIniAudit;

use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Rules\Rule;

/** Render audit results as text, JSON, SARIF or Markdown. */
final class Report
{
    private const COLORS = [
        Severity::CRITICAL => "\033[1;97;41m",
        Severity::HIGH => "\033[1;31m",
        Severity::MEDIUM => "\033[33m",
        Severity::LOW => "\033[36m",
        Severity::INFO => "\033[2m",
    ];
    private const RESET = "\033[0m";
    private const SARIF_LEVEL = [
        Severity::CRITICAL => 'error',
        Severity::HIGH => 'error',
        Severity::MEDIUM => 'warning',
        Severity::LOW => 'note',
        Severity::INFO => 'note',
    ];
    private const SECURITY_SEVERITY = [
        Severity::CRITICAL => '9.5',
        Severity::HIGH => '8.0',
        Severity::MEDIUM => '5.5',
        Severity::LOW => '3.0',
        Severity::INFO => '0.0',
    ];

    /** @return list<int> */
    private static function severitiesDescending(): array
    {
        $severities = array_keys(Severity::NAMES);
        rsort($severities);
        return $severities;
    }

    /**
     * @param iterable<Finding> $findings
     * @return array<string, int>
     */
    public static function severityCounts(iterable $findings): array
    {
        $counts = [];
        foreach ($findings as $finding) {
            $counts[$finding->severity] = ($counts[$finding->severity] ?? 0) + 1;
        }
        $result = [];
        foreach (self::severitiesDescending() as $severity) {
            $result[Severity::name($severity)] = $counts[$severity] ?? 0;
        }
        return $result;
    }

    public static function summary(AuditResult $result): array
    {
        $byCategory = [];
        $byTarget = [];
        foreach ($result->findings as $finding) {
            $byCategory[$finding->category] = ($byCategory[$finding->category] ?? 0) + 1;
            $severity = Severity::name($finding->severity);
            $byTarget[$finding->target][$severity] = ($byTarget[$finding->target][$severity] ?? 0) + 1;
        }
        $pairs = [];
        foreach ($byCategory as $category => $count) {
            $pairs[] = [(string) $category, $count];
        }
        $sortedCategories = [];
        foreach (Util::sortBy($pairs, static function (array $pair): int {
            return -$pair[1];
        }) as [$category, $count]) {
            $sortedCategories[$category] = $count;
        }
        $overlays = 0;
        foreach ($result->targets as $target) {
            if ($target->overlay !== null && $target->overlay !== '') {
                $overlays++;
            }
        }
        return [
            'by_severity' => self::severityCounts($result->findings),
            'by_category' => $sortedCategories,
            'by_target' => $byTarget,
            'rules_evaluated' => $result->rulesEvaluated,
            'configurations' => count($result->targets) - $overlays,
            'overlays' => $overlays,
            'files' => count($result->files),
            'path_checks' => $result->pathChecks,
        ];
    }

    private static function where(Finding $finding): string
    {
        if ($finding->location !== null) {
            return (string) $finding->location;
        }
        return $finding->fromDefault ? 'built-in default' : '';
    }

    public static function renderText(AuditResult $result, string $profile, bool $color = false): string
    {
        $paint = static function (int $severity, string $text) use ($color): string {
            return $color ? self::COLORS[$severity] . $text . self::RESET : $text;
        };

        $lines = [sprintf('php-ini-audit %s  profile=%s  path-checks=%s', Version::VERSION, $profile,
            $result->pathChecks ? 'on' : 'off')];
        if (!$result->targets) {
            $lines[] = 'No PHP configuration found. Pass paths, --ini or --root.';
        }
        foreach ($result->warnings as $warning) {
            $lines[] = "warning: $warning";
        }

        $grouped = [];
        foreach ($result->findings as $finding) {
            $grouped[$finding->target][] = $finding;
        }

        $targetNames = [];
        $describe = [];
        foreach ($result->targets as $target) {
            $targetNames[] = $target->name();
            $describe[$target->name()] = $target;
        }
        $fileOnly = array_values(array_diff(array_map('strval', array_keys($grouped)), $targetNames));
        sort($fileOnly, SORT_STRING);
        $targetNames = array_merge($targetNames, array_values(array_unique($fileOnly)));
        foreach ($targetNames as $name) {
            $findings = $grouped[$name] ?? [];
            $target = $describe[$name] ?? null;
            $lines[] = '';
            $header = "== $name";
            if ($target !== null) {
                $version = Versions::formatVersion($target->phpVersion);
                if ($target->versionSource !== null && $target->versionSource !== '' && $target->versionSource !== 'path') {
                    $version .= " from {$target->versionSource}";
                }
                $header .= "  [sapi {$target->sapi}, php $version]";
            } else {
                $header .= '  [file checks]';
            }
            $lines[] = $header;
            if ($target !== null && $target->files && ($target->overlay === null || $target->overlay === '')) {
                $lines[] = '   files: ' . implode(', ', $target->files);
            }
            if ($findings) {
                $parts = [];
                foreach (self::severityCounts($findings) as $severity => $count) {
                    $parts[] = "$count $severity";
                }
                $lines[] = '   ' . implode(', ', $parts);
            } else {
                $lines[] = '   no findings';
            }
            foreach ($findings as $finding) {
                $label = $paint($finding->severity, self::pad(strtoupper(Severity::name($finding->severity)), 8));
                $lines[] = sprintf('  %s %s %s  (confidence %s)', $label, self::pad($finding->ruleId, 14),
                    $finding->title, Confidence::name($finding->confidence));
                $lines[] = "           {$finding->message}";
                $where = self::where($finding);
                if ($where !== '') {
                    $lines[] = "           at $where";
                }
                $lines[] = "           fix: {$finding->recommendation}";
            }
        }

        $data = self::summary($result);
        $lines[] = '';
        $lines[] = 'Summary';
        $lines[] = sprintf('  %d configuration(s), %d overlay(s), %d file(s), %d rules', $data['configurations'],
            $data['overlays'], $data['files'], $data['rules_evaluated']);
        $parts = [];
        foreach ($data['by_severity'] as $severity => $count) {
            $parts[] = "$severity $count";
        }
        $lines[] = '  severity: ' . implode('  ', $parts);
        if ($data['by_category']) {
            $parts = [];
            foreach ($data['by_category'] as $category => $count) {
                $parts[] = "$category $count";
            }
            $lines[] = '  category: ' . implode('  ', $parts);
        }
        return implode("\n", $lines) . "\n";
    }

    public static function renderJson(AuditResult $result, string $profile): string
    {
        $summary = self::summary($result);
        $summary['by_category'] = (object) $summary['by_category'];
        $byTarget = [];
        foreach ($summary['by_target'] as $name => $counts) {
            $byTarget[(string) $name] = (object) $counts;
        }
        $summary['by_target'] = (object) $byTarget;
        $payload = [
            'tool' => ['name' => 'php-ini-audit', 'version' => Version::VERSION],
            'profile' => $profile,
            'summary' => $summary,
            'targets' => array_map(static function (Target $t): array {
                return $t->toArray();
            }, $result->targets),
            'files' => $result->files,
            'warnings' => $result->warnings,
            'findings' => array_map(static function (Finding $f): array {
                return $f->toArray();
            }, $result->findings),
        ];
        return self::jsonDumps($payload) . "\n";
    }

    public static function renderSarif(AuditResult $result, string $profile): string
    {
        $used = [];
        foreach ($result->findings as $finding) {
            $used[$finding->ruleId] = true;
        }
        $used = array_map('strval', array_keys($used));
        sort($used, SORT_STRING);
        $registry = Registry::all();
        $rules = [];
        foreach ($used as $ruleId) {
            $rule = $registry[$ruleId];
            $tags = ['security', $rule->categoryName()];
            if ($rule->cwe !== null && $rule->cwe !== '') {
                $tags[] = $rule->cwe;
            }
            $descriptor = [
                'id' => $rule->id,
                'name' => $rule->title,
                'shortDescription' => ['text' => $rule->title],
                'fullDescription' => ['text' => $rule->description],
                'help' => ['text' => $rule->recommendation],
                'properties' => [
                    'category' => $rule->categoryName(),
                    'tags' => $tags,
                    'security-severity' => self::SECURITY_SEVERITY[$rule->severity],
                ],
            ];
            if ($rule->references) {
                $descriptor['helpUri'] = $rule->references[0];
            }
            $rules[] = $descriptor;
        }
        $results = [];
        foreach ($result->findings as $finding) {
            $item = [
                'ruleId' => $finding->ruleId,
                'level' => self::SARIF_LEVEL[$finding->severity],
                'message' => ['text' => "{$finding->message} [{$finding->target}]"],
                'properties' => [
                    'severity' => Severity::name($finding->severity),
                    'confidence' => Confidence::name($finding->confidence),
                    'target' => $finding->target,
                    'security-severity' => self::SECURITY_SEVERITY[$finding->severity],
                    'fromDefault' => $finding->fromDefault,
                ],
            ];
            if ($finding->location !== null) {
                $physical = ['artifactLocation' => ['uri' => $finding->location->path]];
                if ($finding->location->line) {
                    $physical['region'] = ['startLine' => $finding->location->line];
                }
                $item['locations'] = [['physicalLocation' => $physical]];
            }
            $results[] = $item;
        }
        $document = [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'php-ini-audit',
                            'version' => Version::VERSION,
                            'rules' => $rules,
                        ],
                    ],
                    'properties' => ['profile' => $profile],
                    'results' => $results,
                ],
            ],
        ];
        return self::jsonDumps($document) . "\n";
    }

    private static function mdEscape(string $text): string
    {
        return str_replace(['|', "\n"], ['\\|', ' '], $text);
    }

    public static function renderMarkdown(AuditResult $result, string $profile): string
    {
        $data = self::summary($result);
        $lines = [
            '# PHP configuration audit',
            '',
            sprintf('Profile: **%s** · path checks: **%s** · %d configuration(s), %d overlay(s), %d file(s)', $profile,
                $result->pathChecks ? 'on' : 'off', $data['configurations'], $data['overlays'], $data['files']),
            '',
            '| Severity | Findings |',
            '| --- | ---: |',
        ];
        foreach ($data['by_severity'] as $severity => $count) {
            $lines[] = "| $severity | $count |";
        }
        $lines[] = '';
        foreach (self::severitiesDescending() as $severity) {
            $findings = array_filter($result->findings, static function (Finding $f) use ($severity): bool {
                return $f->severity === $severity;
            });
            if (!$findings) {
                continue;
            }
            array_push($lines, '## ' . ucfirst(Severity::name($severity)), '',
                '| Rule | Finding | Location | Target | Confidence |', '| --- | --- | --- | --- | --- |');
            foreach ($findings as $f) {
                $lines[] = sprintf('| %s | **%s** — %s | %s | %s | %s |', $f->ruleId, self::mdEscape($f->title),
                    self::mdEscape($f->message), self::mdEscape(self::where($f)), self::mdEscape($f->target),
                    Confidence::name($f->confidence));
            }
            $lines[] = '';
        }
        return implode("\n", $lines) . "\n";
    }

    public static function renderRules(string $format): string
    {
        $registry = Registry::all();
        ksort($registry, SORT_STRING);
        $rules = array_values($registry);
        if ($format === 'json') {
            return self::jsonDumps(array_map(static function (Rule $r): array {
                $sapis = null;
                if ($r->sapis) {
                    $sapis = $r->sapis;
                    sort($sapis, SORT_STRING);
                }
                return [
                    'id' => $r->id,
                    'title' => $r->title,
                    'category' => $r->categoryName(),
                    'severity' => Severity::name($r->severity),
                    'scope' => $r->scope,
                    'sapis' => $sapis,
                    'production_only' => $r->productionOnly,
                    'directives' => array_values($r->directives),
                    'description' => $r->description,
                    'recommendation' => $r->recommendation,
                    'cwe' => $r->cwe,
                    'references' => array_values($r->references),
                ];
            }, $rules)) . "\n";
        }
        if ($format === 'markdown') {
            $lines = ['| Rule | Severity | Category | Title |', '| --- | --- | --- | --- |'];
            foreach ($rules as $r) {
                $lines[] = sprintf('| %s | %s | %s | %s |', $r->id, Severity::name($r->severity), $r->categoryName(),
                    self::mdEscape($r->title));
            }
            return implode("\n", $lines) . "\n";
        }
        $output = '';
        foreach ($rules as $r) {
            $output .= sprintf("%s %s %s %s\n", self::pad($r->id, 14), self::pad(Severity::name($r->severity), 8),
                self::pad($r->categoryName(), 30), $r->title);
        }
        return $output;
    }

    public static function renderRule(string $ruleId): string
    {
        $rule = Registry::all()[$ruleId];
        $severity = 'severity:   ' . Severity::name($rule->severity);
        if ($rule->devSeverity !== null) {
            $severity .= ' (development: ' . Severity::name($rule->devSeverity) . ')';
        }
        $scope = "scope:      {$rule->scope}";
        if ($rule->sapis) {
            $sapis = $rule->sapis;
            sort($sapis, SORT_STRING);
            $scope .= ', SAPIs: ' . implode(', ', $sapis);
        }
        $lines = ["{$rule->id}  {$rule->title}", $severity, 'category:   ' . $rule->categoryName(), $scope];
        if ($rule->directives) {
            $lines[] = 'directives: ' . implode(', ', $rule->directives);
        }
        if ($rule->cwe !== null && $rule->cwe !== '') {
            $lines[] = "weakness:   {$rule->cwe}";
        }
        array_push($lines, '', $rule->description, '', "Fix: {$rule->recommendation}");
        foreach ($rule->references as $reference) {
            $lines[] = "See: $reference";
        }
        return implode("\n", $lines) . "\n";
    }

    /** Left-align $text in $width characters (not bytes). */
    private static function pad(string $text, int $width): string
    {
        $length = preg_match_all('/./su', $text);
        $length = $length === false ? strlen($text) : $length;
        return $length >= $width ? $text : $text . str_repeat(' ', $width - $length);
    }

    /**
     * JSON with 2-space indentation, non-ASCII escaped and "/" unescaped.
     * Arrays with keys 0..n-1 (and empty arrays) encode as lists; use objects for dicts that may be empty.
     */
    public static function jsonDumps($value, int $level = 0): string
    {
        if ($value === null) {
            return 'null';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_float($value)) {
            return self::jsonFloat($value);
        }
        if (is_string($value)) {
            return self::jsonString($value);
        }
        $isObject = is_object($value);
        $items = $isObject ? get_object_vars($value) : $value;
        if (!$isObject && ($items === [] || array_keys($items) === range(0, count($items) - 1))) {
            if ($items === []) {
                return '[]';
            }
            $parts = [];
            foreach ($items as $item) {
                $parts[] = self::jsonDumps($item, $level + 1);
            }
            return self::jsonContainer('[', ']', $parts, $level);
        }
        if ($items === []) {
            return '{}';
        }
        $parts = [];
        foreach ($items as $key => $item) {
            $parts[] = self::jsonString((string) $key) . ': ' . self::jsonDumps($item, $level + 1);
        }
        return self::jsonContainer('{', '}', $parts, $level);
    }

    private static function jsonContainer(string $open, string $close, array $parts, int $level): string
    {
        $inner = "\n" . str_repeat('  ', $level + 1);
        return $open . $inner . implode(',' . $inner, $parts) . "\n" . str_repeat('  ', $level) . $close;
    }

    private static function jsonFloat(float $value): string
    {
        if (is_nan($value)) {
            return 'NaN';
        }
        if (is_infinite($value)) {
            return $value > 0 ? 'Infinity' : '-Infinity';
        }
        $text = var_export($value, true);
        return $text;
    }

    private static function jsonString(string $text): string
    {
        if (!preg_match('//u', $text)) {
            $text = self::replaceInvalidUtf8($text);
        }
        $escaped = preg_replace_callback('/[^\x20\x21\x23-\x5b\x5d-\x7e]/u', static function (array $m): string {
            $map = ['"' => '\\"', '\\' => '\\\\', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t', "\x08" => '\\b',
                "\x0c" => '\\f'];
            if (isset($map[$m[0]])) {
                return $map[$m[0]];
            }
            $code = self::codepoint($m[0]);
            if ($code >= 0x10000) {
                $code -= 0x10000;
                return sprintf('\\u%04x\\u%04x', 0xd800 | ($code >> 10), 0xdc00 | ($code & 0x3ff));
            }
            return sprintf('\\u%04x', $code);
        }, $text);
        return '"' . $escaped . '"';
    }

    private static function codepoint(string $char): int
    {
        $bytes = array_values(unpack('C*', $char));
        $count = count($bytes);
        if ($count === 1) {
            return $bytes[0];
        }
        $code = $bytes[0] & (0xff >> ($count + 1));
        for ($i = 1; $i < $count; $i++) {
            $code = ($code << 6) | ($bytes[$i] & 0x3f);
        }
        return $code;
    }

    /** Like bytes.decode("utf-8", errors="replace"). */
    private static function replaceInvalidUtf8(string $text): string
    {
        $valid = '/\G(?:[\x00-\x7f]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee\xef][\x80-\xbf]{2}'
            . '|\xed[\x80-\x9f][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2})+/';
        $result = '';
        $offset = 0;
        $length = strlen($text);
        while ($offset < $length) {
            if (preg_match($valid, $text, $m, 0, $offset)) {
                $result .= $m[0];
                $offset += strlen($m[0]);
                continue;
            }
            $result .= "\u{fffd}";
            $offset++;
        }
        return $result;
    }
}

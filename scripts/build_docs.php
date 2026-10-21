<?php
/**
 * Fill the generated regions of docs/*.html from the rule registry.
 *
 * Usage: php scripts/build_docs.php [--check]
 *
 * Also bundles the scanner into docs/assets/php-ini-audit.php for the in-browser phpinfo() scanner.
 */

use PhpIniAudit\Rules\Base;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Rules\Rule;
use PhpIniAudit\Severity;
use PhpIniAudit\Version;

require __DIR__ . '/bundle.php';

const DOCS = __DIR__ . '/../docs';
const BUNDLE = DOCS . '/assets/php-ini-audit.php';
const INI_DUMP = DOCS . '/assets/ini-dump.php';
const REGION = '/(<!-- generated:(?P<name>[a-z-]+) -->)(.*?)(<!-- \/generated:(?P=name) -->)/s';

function esc(string $text): string
{
    return str_replace('&#039;', '&#x27;', htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));
}

function rule_html(Rule $rule): string
{
    $severity = Severity::name($rule->severity);
    $meta = ['<span><b>Category</b> ' . esc($rule->categoryName()) . '</span>', "<span><b>Scope</b> {$rule->scope}</span>"];
    if ($rule->sapis) {
        $sapis = $rule->sapis;
        sort($sapis, SORT_STRING);
        $meta[] = '<span><b>SAPIs</b> ' . esc(implode(', ', $sapis)) . '</span>';
    }
    if ($rule->productionOnly) {
        $meta[] = '<span><b>Profile</b> production only</span>';
    }
    if ($rule->devSeverity !== null) {
        $meta[] = '<span><b>Development</b> ' . Severity::name($rule->devSeverity) . '</span>';
    }
    if ($rule->cwe !== null) {
        $number = explode('-', $rule->cwe, 2)[1];
        $meta[] = "<span><b>Weakness</b> <a href=\"https://cwe.mitre.org/data/definitions/$number.html\">{$rule->cwe}</a></span>";
    }
    $directives = '';
    if ($rule->directives) {
        $directives = '<p><b>Directives</b> ' . implode(', ', array_map(static function (string $d): string {
            return '<code>' . esc($d) . '</code>';
        }, $rule->directives)) . '</p>';
    }
    $references = '';
    if ($rule->references) {
        $links = implode('', array_map(static function (string $r): string {
            return '<li><a href="' . esc($r) . '">' . esc($r) . '</a></li>';
        }, $rule->references));
        $references = "<ul>$links</ul>";
    }
    $search = strtolower(implode(' ', [$rule->id, $rule->title, $rule->description, implode(' ', $rule->directives),
        $rule->cwe ?? '']));
    return "<details class=\"rule\" id=\"{$rule->id}\" data-severity=\"$severity\" data-category=\"{$rule->category()}\" "
        . 'data-search="' . esc($search) . "\">\n"
        . "  <summary><span class=\"id\">{$rule->id}</span><span class=\"title\">" . esc($rule->title) . '</span>'
        . "<span class=\"sev sev-$severity\">$severity</span></summary>\n"
        . "  <div class=\"body\">\n"
        . '    <div class="meta">' . implode('', $meta) . "</div>\n"
        . '    <p>' . esc($rule->description) . "</p>\n"
        . "    $directives\n"
        . '    <p class="fix"><b>Fix:</b> ' . esc($rule->recommendation) . "</p>\n"
        . "    $references\n"
        . "  </div>\n"
        . '</details>';
}

/** @return list<Rule> */
function category_rules(string $category): array
{
    $rules = array_filter(Registry::all(), static function (Rule $r) use ($category): bool {
        return $r->category() === $category;
    });
    ksort($rules, SORT_STRING);
    return array_values($rules);
}

function render_rules(): string
{
    $parts = [];
    foreach (Base::CATEGORIES as $category => $name) {
        $rules = category_rules($category);
        if (!$rules) {
            continue;
        }
        $parts[] = "<section class=\"category\" data-category=\"$category\">\n"
            . "<h2 class=\"category-heading\" id=\"cat-$category\">" . esc($name) . ' '
            . "<a class=\"anchor\" href=\"#cat-$category\">#</a></h2>\n"
            . implode("\n", array_map('rule_html', $rules))
            . "\n</section>";
    }
    return "\n" . implode("\n", $parts) . "\n";
}

function render_severity_options(): string
{
    $options = '';
    foreach (array_reverse(Severity::NAMES) as $name) {
        $options .= "<option value=\"$name\">" . ucfirst($name) . '</option>';
    }
    return "<option value=\"\">All severities</option>$options";
}

function render_category_options(): string
{
    $options = '';
    foreach (Base::CATEGORIES as $category => $name) {
        if (category_rules($category)) {
            $options .= "<option value=\"$category\">" . esc($name) . '</option>';
        }
    }
    return "<option value=\"\">All categories</option>$options";
}

function render_category_table(): string
{
    $rows = [];
    foreach (Base::CATEGORIES as $category => $name) {
        $rules = category_rules($category);
        if ($rules) {
            $rows[] = "<tr><td><a href=\"rules.html#cat-$category\"><code>$category</code></a></td>"
                . '<td>' . esc($name) . '</td><td>' . count($rules) . '</td></tr>';
        }
    }
    return "\n" . implode("\n", $rows) . "\n";
}

function generate(string $name): string
{
    switch ($name) {
        case 'rules':
            return render_rules();
        case 'rule-count':
            return (string) count(Registry::all());
        case 'version':
            return Version::VERSION;
        case 'severity-options':
            return render_severity_options();
        case 'category-options':
            return render_category_options();
        case 'category-table':
            return render_category_table();
        case 'ini-dump':
            return esc(file_get_contents(INI_DUMP));
    }
    throw new RuntimeException("unknown generated region: $name");
}

function build(string $text): string
{
    return preg_replace_callback(REGION, static function (array $match): string {
        return $match[1] . generate($match['name']) . $match[4];
    }, $text);
}

function main(array $argv): int
{
    $check = in_array('--check', $argv, true);
    $stale = [];
    $pages = glob(DOCS . '/*.html');
    sort($pages, SORT_STRING);
    foreach ($pages as $page) {
        $current = file_get_contents($page);
        $updated = build($current);
        if ($updated !== $current) {
            $stale[] = basename($page);
            if (!$check) {
                file_put_contents($page, $updated);
            }
        }
    }
    if ($check && $stale) {
        fwrite(STDERR, 'out of date: ' . implode(', ', $stale) . " (run php scripts/build_docs.php)\n");
        return 1;
    }
    if ($stale && !$check) {
        echo 'updated: ' . implode(', ', $stale) . "\n";
    }
    if (!$check) {
        file_put_contents(BUNDLE, bundle_source());
    }
    return 0;
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    exit(main(array_slice($argv, 1)));
}

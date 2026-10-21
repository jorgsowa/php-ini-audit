<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Directives;
use PhpIniAudit\IniFile;
use PhpIniAudit\Severity;
use PhpIniAudit\SourceKind;
use PhpIniAudit\Util;

/** Configuration hygiene: syntax, obsolete or misspelled directives, overrides that do not apply. */
final class Hygiene
{
    private const LEGACY_PROTECTIONS = ['safe_mode', 'magic_quotes_gpc', 'sql.safe_mode'];
    private const LEGACY_DANGERS = ['register_globals'];

    /** @var list<string>|null */
    private static ?array $knownNames = null;
    /** @var array<string, string> */
    private static array $knownLower = [];
    /** @var array<string, true> */
    private static array $knownPrefixes = [];

    /** @return list<string> sorted names of known and obsolete directives */
    private static function knownNames(): array
    {
        if (self::$knownNames === null) {
            $names = array_map('strval', array_keys(Directives::KNOWN + Directives::OBSOLETE));
            sort($names, SORT_STRING);
            self::$knownNames = $names;
            foreach ($names as $name) {
                self::$knownLower[strtolower($name)] = $name;
                if (strpos($name, '.') !== false) {
                    self::$knownPrefixes[explode('.', $name, 2)[0]] = true;
                }
            }
        }
        return self::$knownNames;
    }

    private static function isLegacyOn(string $value): bool
    {
        return $value !== '' && $value !== '0';
    }

    public static function register(): void
    {
        Registry::rule('CFG-001', 'Syntax problem in configuration file', [
            'severity' => Severity::LOW,
            'scope' => 'file',
            'description' => 'Lines PHP cannot parse are ignored or stop INI parsing at that point, so later settings '
                . 'silently do not apply.',
            'recommendation' => "Fix the reported lines; use ';' for comments.",
        ], static function (FileContext $fctx): iterable {
            foreach ($fctx->file->issues as $issue) {
                yield new Hit($issue->message, [], null, Confidence::HIGH, $issue->location);
            }
        });

        Registry::rule('CFG-002', 'Obsolete directive', [
            'severity' => Severity::INFO,
            'scope' => 'file',
            'description' => 'Directives removed from PHP are ignored. Settings such as safe_mode or magic_quotes_gpc '
                . 'give a false sense of protection; register_globals = On is critical on the old versions that still '
                . 'honour it.',
            'recommendation' => 'Remove obsolete directives and use their modern replacements.',
        ], static function (FileContext $fctx): iterable {
            $version = $fctx->phpVersion;
            foreach ($fctx->file->phpDirectives() as $directive) {
                $removed = Directives::removedIn($directive->name);
                if ($removed === null) {
                    continue;
                }
                $removedVersion = Directives::versionTuple($removed);
                $stillActive = $version !== null && Util::compare($version, $removedVersion) < 0;
                $dangerOn = in_array($directive->name, self::LEGACY_DANGERS, true) && self::isLegacyOn($directive->value);
                if ($stillActive) {
                    if ($dangerOn) {
                        yield new Hit("{$directive->name} = On on PHP {$version[0]}.{$version[1]}", [$directive],
                            Severity::CRITICAL);
                    }
                    continue;
                }
                if ($dangerOn) {
                    yield new Hit(
                        "{$directive->name} is set On; ignored since PHP $removed but critical on older versions",
                        [$directive],
                        $version ? Severity::INFO : Severity::HIGH,
                        $version ? Confidence::HIGH : Confidence::LOW
                    );
                } elseif (in_array($directive->name, self::LEGACY_PROTECTIONS, true)
                    && self::isLegacyOn($directive->value)) {
                    yield new Hit("{$directive->name} was removed in PHP $removed; it no longer protects anything",
                        [$directive], Severity::LOW);
                } else {
                    yield new Hit("{$directive->name} was removed in PHP $removed and is ignored", [$directive]);
                }
            }
        });

        Registry::rule('CFG-003', 'Unknown directive resembling a known one', [
            'severity' => Severity::LOW,
            'scope' => 'file',
            'description' => 'PHP ignores unknown directive names (and names are case-sensitive), so a typo such as '
                . "'display_error' leaves the intended protection unset.",
            'recommendation' => 'Correct the directive name.',
        ], static function (FileContext $fctx): iterable {
            $sensitive = Registry::securityDirectives();
            $known = self::knownNames();
            foreach ($fctx->file->phpDirectives() as $directive) {
                $name = $directive->name;
                if (Directives::isKnown($name) || Directives::removedIn($name) !== null) {
                    continue;
                }
                $suggestion = self::$knownLower[strtolower($name)] ?? null;
                if ($suggestion === null) {
                    $prefix = strpos($name, '.') !== false ? explode('.', $name, 2)[0] : null;
                    if ($prefix !== null && !isset(self::$knownPrefixes[$prefix])) {
                        continue;
                    }
                    $suggestion = self::closeMatch($name, $known, 0.9);
                }
                if ($suggestion !== null) {
                    yield new Hit(
                        'unknown directive ' . Util::repr($name) . '; did you mean ' . Util::repr($suggestion) . '?',
                        [$directive],
                        in_array($suggestion, $sensitive, true) ? Severity::MEDIUM : Severity::LOW,
                        Confidence::MEDIUM
                    );
                }
            }
        });

        Registry::rule('CFG-004', 'Directive redefined with a different value', [
            'severity' => Severity::INFO,
            'description' => 'When php.ini, scan-dir files and pool settings disagree, the last one read wins. '
                . 'Reviewers looking at only one file get the wrong picture.',
            'recommendation' => 'Keep each security directive in one place.',
        ], static function (Context $ctx): iterable {
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
        });

        Registry::rule('CFG-005', 'Per-directory override that PHP ignores', [
            'severity' => Severity::LOW,
            'description' => '.user.ini and .htaccess can only change PHP_INI_PERDIR/PHP_INI_ALL directives. Hardening '
                . 'attempted there for PHP_INI_SYSTEM directives (disable_functions, allow_url_fopen, expose_php, ...) '
                . 'does not take effect.',
            'recommendation' => 'Move the setting to php.ini or to php_admin_value in the FPM pool / Apache vhost.',
        ], static function (Context $ctx): iterable {
            $sensitive = Registry::securityDirectives();
            foreach ($ctx->config->ineffective as $directive) {
                yield new Hit(
                    "{$directive->name} cannot be changed from {$directive->kind} and is ignored",
                    [$directive],
                    in_array($directive->name, $sensitive, true) ? Severity::LOW : Severity::INFO
                );
            }
        });

        Registry::rule('CFG-006', 'No php.ini loaded: built-in defaults in effect', [
            'severity' => Severity::MEDIUM,
            'description' => 'Without php.ini, PHP runs with compiled-in defaults: display_errors = On, '
                . 'register_argc_argv = On, expose_php = On, enable_dl = On and no disable_functions. Official Docker '
                . 'images ship this way.',
            'recommendation' => 'Copy php.ini-production to php.ini and adjust it.',
        ], static function (Context $ctx): iterable {
            if ($ctx->defaultsReason !== null && $ctx->defaultsReason !== '') {
                yield new Hit($ctx->defaultsReason);
            }
        });

        Registry::rule('CFG-007', 'Value depends on an environment variable', [
            'severity' => Severity::INFO,
            'scope' => 'file',
            'description' => '${VAR} is expanded by PHP at start-up from its own environment, so a static audit cannot '
                . 'know the effective value; rules evaluated the literal text.',
            'recommendation' => 'Check the variable in the PHP process environment, or use a literal value.',
        ], static function (FileContext $fctx): iterable {
            $sensitive = Registry::securityDirectives();
            foreach ($fctx->file->phpDirectives() as $directive) {
                if ($directive->unresolved) {
                    yield new Hit("{$directive->name} = {$directive->raw}", [$directive],
                        in_array($directive->name, $sensitive, true) ? Severity::LOW : Severity::INFO);
                }
            }
        });

        Registry::rule('CFG-008', 'Development configuration used in production', [
            'severity' => Severity::LOW,
            'production_only' => true,
            'directives' => ['display_errors', 'zend.assertions', 'mysqlnd.collect_memory_statistics'],
            'description' => 'The combination of display_errors, zend.assertions and mysqlnd memory statistics matches '
                . 'php.ini-development.',
            'recommendation' => 'Start from php.ini-production.',
        ], static function (Context $ctx): iterable {
            $display = $ctx->get('display_errors');
            $markers = [];
            foreach (['zend.assertions', 'mysqlnd.collect_memory_statistics'] as $name) {
                $setting = $ctx->get($name);
                if ($setting->isSet() && $setting->asInt() === 1) {
                    $markers[] = $setting;
                }
            }
            if ($display->isSet() && $display->asBool() && $markers) {
                yield new Hit('settings match php.ini-development', array_merge([$display], $markers), null,
                    Confidence::MEDIUM);
            }
        });

        Registry::rule('CFG-009', 'Conditional [PATH=]/[HOST=] section', [
            'severity' => Severity::INFO,
            'scope' => 'file',
            'description' => 'Directives in [PATH=...] or [HOST=...] sections apply only to matching requests under '
                . 'CGI/FastCGI; they are audited as separate overlays.',
            'recommendation' => 'Verify these sections still match deployed paths and hosts.',
        ], static function (FileContext $fctx): iterable {
            $sections = $fctx->file instanceof IniFile ? $fctx->file->conditionalSections : [];
            foreach ($sections as [$section, $location]) {
                yield new Hit("[$section] overrides settings for matching requests", [], null, Confidence::HIGH,
                    $location);
            }
        });

        Registry::rule('CFG-010', 'Deprecated directive', [
            'severity' => Severity::INFO,
            'scope' => 'file',
            'description' => 'Deprecated directives set to a non-default value still work but emit warnings and will '
                . 'disappear in a future release.',
            'recommendation' => 'Plan to remove the directive; remove it now from .user.ini/.htaccess on PHP versions '
                . 'affected by CVE-2026-109619.',
        ], static function (FileContext $fctx): iterable {
            // Per-request deprecation warnings fire before request state is initialised, a CVE-2026-109619 trigger.
            $perRequest = in_array($fctx->file->kind, [SourceKind::USER_INI, SourceKind::HTACCESS], true)
                && Vulnerabilities::exposedTo('CVE-2026-109619', $fctx->phpVersion);
            foreach ($fctx->file->phpDirectives() as $directive) {
                $since = Directives::DEPRECATED[$directive->name] ?? null;
                if ($since === null) {
                    continue;
                }
                if ($fctx->phpVersion !== null
                    && Util::compare($fctx->phpVersion, Directives::versionTuple($since)) < 0) {
                    continue;
                }
                if ($directive->value === Directives::default($directive->name)) {
                    continue;
                }
                if ($perRequest) {
                    yield new Hit("{$directive->name} is deprecated since PHP $since and its per-request warning can "
                        . 'trigger CVE-2026-109619', [$directive], Severity::MEDIUM);
                } else {
                    yield new Hit("{$directive->name} is deprecated since PHP $since", [$directive]);
                }
            }
        });
    }

    private static function orEmpty(string $value): string
    {
        return $value === '' ? '(empty)' : $value;
    }

    /** The most similar candidate by Ratcliff/Obershelp ratio at or above $cutoff, or null. */
    private static function closeMatch(string $word, array $possibilities, float $cutoff): ?string
    {
        $b = self::chars($word);
        $lb = count($b);
        $b2j = [];
        foreach ($b as $j => $char) {
            $b2j[$char][] = $j;
        }
        $best = null;
        $bestScore = -1.0;
        foreach ($possibilities as $candidate) {
            $a = self::chars($candidate);
            $la = count($a);
            $total = $la + $lb;
            // real_quick_ratio(): an upper bound that skips most candidates cheaply.
            if (($total ? 2.0 * min($la, $lb) / $total : 1.0) < $cutoff) {
                continue;
            }
            $score = $total ? 2.0 * self::matchingCharacters($a, $b2j, $la, $lb) / $total : 1.0;
            if ($score < $cutoff) {
                continue;
            }
            if ($score > $bestScore || ($score === $bestScore && strcmp($candidate, (string) $best) > 0)) {
                $best = $candidate;
                $bestScore = $score;
            }
        }
        return $best;
    }

    /** @return list<string> */
    private static function chars(string $text): array
    {
        $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        return $chars === false ? str_split($text) : $chars;
    }

    /** Total size of SequenceMatcher.get_matching_blocks() for a junk-free sequence pair. */
    private static function matchingCharacters(array $a, array $b2j, int $la, int $lb): int
    {
        $queue = [[0, $la, 0, $lb]];
        $matches = 0;
        while ($queue) {
            [$alo, $ahi, $blo, $bhi] = array_pop($queue);
            $besti = $alo;
            $bestj = $blo;
            $bestsize = 0;
            $j2len = [];
            for ($i = $alo; $i < $ahi; $i++) {
                $newj2len = [];
                foreach ($b2j[$a[$i]] ?? [] as $j) {
                    if ($j < $blo) {
                        continue;
                    }
                    if ($j >= $bhi) {
                        break;
                    }
                    $k = $newj2len[$j] = ($j2len[$j - 1] ?? 0) + 1;
                    if ($k > $bestsize) {
                        $besti = $i - $k + 1;
                        $bestj = $j - $k + 1;
                        $bestsize = $k;
                    }
                }
                $j2len = $newj2len;
            }
            if ($bestsize) {
                $matches += $bestsize;
                if ($alo < $besti && $blo < $bestj) {
                    $queue[] = [$alo, $besti, $blo, $bestj];
                }
                if ($besti + $bestsize < $ahi && $bestj + $bestsize < $bhi) {
                    $queue[] = [$besti + $bestsize, $ahi, $bestj + $bestsize, $bhi];
                }
            }
        }
        return $matches;
    }
}

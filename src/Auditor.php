<?php

namespace PhpIniAudit;

use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Rules\Rule;

/** Turn discovered files into audit targets and evaluate every rule against them. */
final class Auditor
{
    public const PROFILES = ['production', 'development'];
    private const WINDOWS_PATH = '/^[A-Za-z]:[\\\\\/]/';

    public FileSystem $fs;
    public Options $options;
    public ?PathInspector $paths;
    /** @var array<string, IniFile|FpmFile|HtaccessFile|null> */
    public array $parsed = [];
    /** @var array<string, list<int>|null> */
    public array $fileVersions = [];
    /** @var list<string> */
    public array $warnings = [];

    public function __construct(FileSystem $fs, Options $options)
    {
        $this->fs = $fs;
        $this->options = $options;
        $this->paths = $options->pathChecks ? new PathInspector($fs, $options->webroots) : null;
    }

    /** @return list<Rule> */
    public static function selectedRules(Options $options): array
    {
        $matches = static function (Rule $rule, array $selectors): bool {
            foreach ($selectors as $selector) {
                if ($rule->id === strtoupper($selector) || $rule->category() === strtoupper($selector)) {
                    return true;
                }
            }
            return false;
        };
        $rules = Registry::all();
        ksort($rules, SORT_STRING);
        $rules = array_values($rules);
        if ($options->only) {
            $rules = array_filter($rules, static function (Rule $r) use ($matches, $options): bool {
                return $matches($r, $options->only);
            });
        }
        return array_values(array_filter($rules, static function (Rule $r) use ($matches, $options): bool {
            return !$matches($r, $options->skip);
        }));
    }

    /** @return IniFile|FpmFile|HtaccessFile|null */
    private function load(string $path, callable $parser, ...$args)
    {
        if (array_key_exists($path, $this->parsed)) {
            return $this->parsed[$path];
        }
        try {
            $text = $this->fs->readText($path);
        } catch (ReadError $exception) {
            $this->warnings[] = $exception->getMessage();
            $this->parsed[$path] = null;
            return null;
        }
        return $this->parsed[$path] = $parser($text, $path, ...$args);
    }

    private function rememberVersion(string $path, ?array $version): void
    {
        if (($this->fileVersions[$path] ?? null) === null) {
            $this->fileVersions[$path] = $version;
        }
    }

    /** @return list<Target> */
    public function buildTargets(Discovery $discovery): array
    {
        array_push($this->warnings, ...$discovery->warnings);
        $targets = [];
        foreach ($discovery->installations as $installation) {
            array_push($targets, ...$this->installationTargets($installation));
        }
        $overlays = [
            [$discovery->userInis, OverlayKind::USER_INI, ['fpm', 'cgi', 'litespeed', 'unknown']],
            [$discovery->htaccess, OverlayKind::HTACCESS, ['apache2', 'unknown']],
        ];
        foreach ($overlays as [$paths, $kind, $sapis]) {
            foreach ($paths as $path) {
                if ($kind === OverlayKind::USER_INI) {
                    $parsed = $this->load($path, [Parser::class, 'parseIni'], SourceKind::USER_INI);
                } else {
                    $parsed = $this->load($path, [Parser::class, 'parseHtaccess']);
                }
                if ($parsed === null) {
                    continue;
                }
                $hosts = array_values(array_filter($targets, static function (Target $t) use ($sapis): bool {
                    return $t->overlay === null && in_array($t->sapi, $sapis, true);
                }));
                if (!$hosts) {
                    $defaults = new Target('PHP built-in defaults', $this->options->sapi ?? 'unknown',
                        $this->options->phpVersion, [], new EffectiveConfig([]));
                    $defaults->synthetic = true;
                    $targets[] = $defaults;
                    $hosts = [$defaults];
                }
                foreach ($hosts as $host) {
                    $targets[] = $this->overlay($host, $parsed->phpDirectives(), $kind, $path, $path);
                }
            }
        }
        return $targets;
    }

    /** @return list<Target> */
    private function installationTargets(Installation $installation): array
    {
        if ($this->options->phpVersion) {
            [$version, $source, $backports] = [$this->options->phpVersion, '--php-version', false];
        } else {
            $version = $installation->phpVersion;
            $source = $installation->versionSource ?? ($version ? 'path' : null);
            $backports = $installation->versionBackports;
        }
        $layers = [];
        $files = [];
        $iniFiles = [];
        $sources = $installation->ini ? [[$installation->ini, SourceKind::PHP_INI]] : [];
        foreach ($installation->scanFiles as $file) {
            $sources[] = [$file, SourceKind::SCAN_DIR];
        }
        foreach ($sources as [$path, $kind]) {
            $parsed = $this->load($path, [Parser::class, 'parseIni'], $kind);
            if ($parsed === null) {
                continue;
            }
            $this->rememberVersion($path, $version);
            $iniFiles[] = $parsed;
            $files[] = $path;
            array_push($layers, ...$parsed->baseDirectives());
        }
        $pools = [];
        foreach ($installation->fpmFiles as $path) {
            $parsed = $this->load($path, [Parser::class, 'parseFpm']);
            if ($parsed !== null) {
                $this->rememberVersion($path, $version);
                array_push($pools, ...$parsed->pools);
            }
        }
        $base = new Target($installation->label, $this->options->sapi ?? $installation->sapi, $version, $files,
            new EffectiveConfig($layers));
        $base->versionSource = $source;
        $base->versionBackports = $backports;
        $base->platform = $this->platform(
            array_merge([$installation->ini ?? ''], $installation->scanFiles, $installation->fpmFiles), $layers);
        $base->layers = $layers;
        $base->pools = $pools;
        $base->defaultsReason = $installation->defaultsReason;
        $targets = [$base];
        foreach ($iniFiles as $ini) {
            $sections = [];
            foreach ($ini->directives as $directive) {
                if (Parser::isConditional($directive->section)) {
                    $sections[$directive->section][] = $directive;
                }
            }
            foreach ($sections as $section => $conditional) {
                $targets[] = $this->overlay($base, $conditional, OverlayKind::SECTION, "[$section]");
            }
        }
        foreach ($pools as $pool) {
            $label = "pool [{$pool->name}] ({$pool->location->path})";
            $poolTarget = $this->overlay($base, $pool->php, OverlayKind::FPM_POOL, $label, $pool->location->path);
            $poolTarget->sapi = $this->options->sapi ?? 'fpm';
            $poolTarget->pool = $pool;
            $targets[] = $poolTarget;
        }
        return $targets;
    }

    /**
     * @param list<string> $paths
     * @param list<Directive> $layers
     */
    private function platform(array $paths, array $layers): string
    {
        foreach ($paths as $path) {
            if (preg_match(self::WINDOWS_PATH, $path)) {
                return 'windows';
            }
        }
        foreach ($layers as $directive) {
            if (in_array($directive->name, ['extension', 'zend_extension', 'extension_dir'], true)
                && (preg_match(self::WINDOWS_PATH, $directive->value)
                    || Util::endsWith(strtolower($directive->value), '.dll'))) {
                return 'windows';
            }
        }
        if ($this->fs->root === null && PHP_OS_FAMILY === 'Windows') {
            return 'windows';
        }
        return 'posix';
    }

    /** @param list<Directive> $overlay */
    private function overlay(Target $base, array $overlay, string $kind, string $label, ?string $source = null): Target
    {
        $sources = [];
        foreach ($overlay as $directive) {
            $sources[$directive->location->path] = true;
        }
        if ($source !== null && $source !== '') {
            $sources[$source] = true;
        }
        $extra = array_diff(array_map('strval', array_keys($sources)), $base->files);
        sort($extra, SORT_STRING);
        $target = new Target($base->label, $base->sapi, $base->phpVersion, array_merge($base->files, $extra),
            new EffectiveConfig($base->layers, $overlay, $kind));
        $target->versionSource = $base->versionSource;
        $target->versionBackports = $base->versionBackports;
        $target->platform = $base->platform;
        $target->layers = $base->layers;
        $target->overlay = $kind === OverlayKind::FPM_POOL ? $label : "$kind: $label";
        $target->pools = $base->pools;
        return $target;
    }

    public function run(Discovery $discovery): AuditResult
    {
        return $this->evaluate($this->buildTargets($discovery));
    }

    /** @param list<Target> $targets */
    public function evaluate(array $targets): AuditResult
    {
        $rules = self::selectedRules($this->options);
        $findings = [];
        foreach ($targets as $target) {
            if ($target->synthetic) {
                continue;
            }
            $context = new Context($target->config, $target->sapi, $this->options->profile, $target->phpVersion);
            $context->versionSource = $target->versionSource;
            $context->versionBackports = $target->versionBackports;
            $context->platform = $target->platform;
            $context->paths = $this->paths;
            $context->pool = $target->pool;
            $context->pools = $target->pools;
            $context->defaultsReason = $target->defaultsReason;
            $context->overlayKind = $target->config->overlayKind;
            foreach ($rules as $rule) {
                if (!$this->applies($rule, $target)) {
                    continue;
                }
                foreach ($rule->check($context) as $hit) {
                    if ($target->overlay !== null && $rule->scope === 'config' && !self::touchesOverlay($hit, $target)) {
                        continue;
                    }
                    if ($target->observed !== null && !self::observed($hit, $target->observed)) {
                        continue;
                    }
                    $findings[] = $this->finding($rule, $hit, $target->name());
                }
            }
        }
        $parsed = $this->parsed;
        ksort($parsed, SORT_STRING);
        foreach ($parsed as $path => $file) {
            if ($file === null) {
                continue;
            }
            $path = (string) $path;
            $version = array_key_exists($path, $this->fileVersions) ? $this->fileVersions[$path] : $this->options->phpVersion;
            $context = new FileContext($file, $this->options->profile, $version, $this->paths);
            foreach ($rules as $rule) {
                if ($rule->scope !== 'file' || ($rule->productionOnly && $this->options->profile !== 'production')) {
                    continue;
                }
                foreach ($rule->check($context) as $hit) {
                    $findings[] = $this->finding($rule, $hit, self::owner($path, $targets));
                }
            }
        }
        $findings = array_filter($findings, function (Finding $f): bool {
            return $f->severity >= $this->options->minSeverity;
        });
        $findings = Util::sortBy($findings, static function (Finding $f): array {
            return [-$f->severity, -$f->confidence, $f->ruleId, $f->target, (string) ($f->location ?? '')];
        });
        $files = [];
        foreach ($parsed as $path => $file) {
            if ($file !== null) {
                $files[] = (string) $path;
            }
        }
        return new AuditResult(
            array_values(array_filter($targets, static function (Target $t): bool {
                return !$t->synthetic;
            })),
            $findings,
            $files,
            $this->warnings,
            count($rules),
            $this->paths !== null
        );
    }

    /**
     * Attribute file-level findings to the narrowest configuration that reads the file.
     * @param list<Target> $targets
     */
    private static function owner(string $path, array $targets): string
    {
        $best = null;
        foreach ($targets as $target) {
            if (!$target->synthetic && in_array($path, $target->files, true)
                && ($best === null || count($target->files) < count($best->files))) {
                $best = $target;
            }
        }
        return $best ? $best->name() : $path;
    }

    private function applies(Rule $rule, Target $target): bool
    {
        if ($rule->scope === 'file') {
            return false;
        }
        if ($rule->scope === 'pool' && $target->pool === null) {
            return false;
        }
        if ($rule->productionOnly && $this->options->profile !== 'production') {
            return false;
        }
        return $rule->sapis === null || in_array($target->sapi, $rule->sapis, true);
    }

    private static function touchesOverlay(Hit $hit, Target $target): bool
    {
        foreach ($hit->evidence as $item) {
            $directive = $item instanceof Setting ? $item->directive : $item;
            if ($target->config->isOverlay($directive) || $target->config->isIneffective($directive)) {
                return true;
            }
        }
        return false;
    }

    /** @param array<string, true> $observed */
    private static function observed(Hit $hit, array $observed): bool
    {
        $settings = array_filter($hit->evidence, static function ($e): bool {
            return $e instanceof Setting;
        });
        if (count($settings) < count($hit->evidence) || !$settings) {
            return true;
        }
        foreach ($settings as $setting) {
            if (isset($observed[$setting->name])) {
                return true;
            }
        }
        return false;
    }

    private function finding(Rule $rule, Hit $hit, string $targetName): Finding
    {
        $severity = $hit->severity ?? $rule->severity;
        if ($this->options->profile === 'development' && $rule->devSeverity !== null) {
            $severity = min($severity, $rule->devSeverity);
        }
        $confidence = $hit->confidence;
        $primary = $hit->evidence[0] ?? null;
        $directiveName = $value = null;
        $location = $hit->location;
        $fromDefault = false;
        if ($primary instanceof Setting) {
            [$directiveName, $value] = [$primary->name, $primary->value];
            $location = $location ?? $primary->location();
            $fromDefault = !$primary->isSet();
            foreach ($hit->evidence as $evidence) {
                if ($evidence instanceof Setting && $evidence->unresolved()) {
                    $confidence = Confidence::LOW;
                }
            }
        } elseif ($primary instanceof Directive) {
            [$directiveName, $value] = [$primary->name, $primary->value];
            $location = $location ?? $primary->location;
        }
        $finding = new Finding($rule->id, $rule->title, $rule->categoryName(), $severity, $confidence, $hit->message,
            $rule->recommendation, $targetName);
        $finding->directive = $directiveName;
        $finding->value = $value;
        $finding->location = $location;
        $finding->fromDefault = $fromDefault;
        $finding->cwe = $rule->cwe;
        $finding->references = $rule->references;
        return $finding;
    }
}

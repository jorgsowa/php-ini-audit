<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Severity;

/**
 * A rule declares its metadata as class constants and implements check() through ConfigRule, PoolRule or FileRule.
 * check() receives a Context (or FileContext for scope "file") and returns iterable<Hit>, usually by yielding.
 */
abstract class Rule
{
    public const ID = '';
    public const TITLE = '';
    public const SEVERITY = Severity::INFO;
    /** Severity under the development profile, when it differs. */
    public const DEV_SEVERITY = null;
    /** Directives the rule reads; they count as security-relevant for the hygiene rules. */
    public const DIRECTIVES = [];
    public const SCOPE = 'config';
    /** SAPIs the rule applies to; null for every SAPI. */
    public const SAPIS = null;
    public const PRODUCTION_ONLY = false;
    public const CWE = null;
    public const DESCRIPTION = '';
    public const RECOMMENDATION = '';
    public const REFERENCES = [];

    public string $id;
    public string $title;
    public int $severity;
    public string $description;
    public string $recommendation;
    /** @var list<string> */
    public array $directives;
    public string $scope;
    /** @var list<string>|null */
    public ?array $sapis;
    public bool $productionOnly;
    public ?int $devSeverity;
    public ?string $cwe;
    /** @var list<string> */
    public array $references;

    public function __construct()
    {
        $this->id = static::ID;
        $this->title = static::TITLE;
        $this->severity = static::SEVERITY;
        $this->description = static::DESCRIPTION;
        $this->recommendation = static::RECOMMENDATION;
        $this->directives = array_values(static::DIRECTIVES);
        $this->scope = static::SCOPE;
        $this->sapis = static::SAPIS === null ? null : array_values(static::SAPIS);
        $this->productionOnly = static::PRODUCTION_ONLY;
        $this->devSeverity = static::DEV_SEVERITY;
        $this->cwe = static::CWE;
        $this->references = array_values(static::REFERENCES);
    }

    public function category(): string
    {
        return explode('-', $this->id, 2)[0];
    }

    public function categoryName(): string
    {
        return Category::NAMES[$this->category()] ?? $this->category();
    }

    /** @param iterable<string> $items */
    protected static function names(iterable $items): string
    {
        return implode(', ', is_array($items) ? $items : iterator_to_array($items, false));
    }
}

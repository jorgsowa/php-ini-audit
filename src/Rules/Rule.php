<?php

namespace PhpIniAudit\Rules;

final class Rule
{
    public string $id;
    public string $title;
    public int $severity;
    public string $description;
    public string $recommendation;
    /** @var callable(Context|FileContext): iterable<Hit> */
    public $check;
    /** @var list<string> */
    public array $directives = [];
    public string $scope = 'config';
    /** @var list<string>|null */
    public ?array $sapis = null;
    public bool $productionOnly = false;
    public ?int $devSeverity = null;
    public ?string $cwe = null;
    /** @var list<string> */
    public array $references = [];

    public function __construct(string $id, string $title, int $severity, string $description, string $recommendation,
        callable $check)
    {
        $this->id = $id;
        $this->title = $title;
        $this->severity = $severity;
        $this->description = $description;
        $this->recommendation = $recommendation;
        $this->check = $check;
    }

    /** @return iterable<Hit> */
    public function check($context): iterable
    {
        return ($this->check)($context) ?? [];
    }

    public function category(): string
    {
        return explode('-', $this->id, 2)[0];
    }

    public function categoryName(): string
    {
        return Base::CATEGORIES[$this->category()] ?? $this->category();
    }
}

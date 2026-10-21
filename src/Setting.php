<?php

namespace PhpIniAudit;

/** Effective value of a directive: the last assignment, or PHP's built-in default. */
final class Setting
{
    public string $name;
    public ?string $value;
    public ?Directive $directive;
    /** @var list<Directive> */
    public array $overridden;

    public function __construct(string $name, ?string $value, ?Directive $directive = null, array $overridden = [])
    {
        $this->name = $name;
        $this->value = $value;
        $this->directive = $directive;
        $this->overridden = $overridden;
    }

    public function isSet(): bool
    {
        return $this->directive !== null;
    }

    public function location(): ?Location
    {
        return $this->directive ? $this->directive->location : null;
    }

    public function unresolved(): bool
    {
        return $this->directive !== null && $this->directive->unresolved;
    }

    public function asBool(): bool
    {
        return Values::toBool($this->value);
    }

    public function asInt(): int
    {
        return Values::atoi($this->value);
    }

    public function asBytes(): ?int
    {
        return Values::toBytes($this->value);
    }

    /** @return list<string> */
    public function asList(): array
    {
        return Values::splitList($this->value);
    }

    public function text(): string
    {
        return trim($this->value ?? '');
    }

    public function describe(): string
    {
        $shown = $this->value === null || $this->value === '' ? '(empty)' : $this->value;
        return "{$this->name} = $shown";
    }
}

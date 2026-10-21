<?php

namespace PhpIniAudit;

/** One assignment as written in a configuration file. */
final class Directive
{
    public string $name;
    public string $value;
    public string $raw;
    public Location $location;
    public string $kind;
    public ?string $section;
    public bool $admin;
    public bool $unresolved;

    public function __construct(string $name, string $value, string $raw, Location $location, string $kind,
        ?string $section = null, bool $admin = false, bool $unresolved = false)
    {
        $this->name = $name;
        $this->value = $value;
        $this->raw = $raw;
        $this->location = $location;
        $this->kind = $kind;
        $this->section = $section;
        $this->admin = $admin;
        $this->unresolved = $unresolved;
    }

    public function withValue(string $value): self
    {
        $copy = clone $this;
        $copy->value = $value;
        return $copy;
    }
}

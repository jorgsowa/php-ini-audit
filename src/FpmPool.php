<?php

namespace PhpIniAudit;

final class FpmPool
{
    public string $name;
    public Location $location;
    /** @var array<string, Directive> */
    public array $settings = [];
    /** @var list<Directive> */
    public array $php = [];
    /** @var list<Directive> */
    public array $env = [];

    public function __construct(string $name, Location $location)
    {
        $this->name = $name;
        $this->location = $location;
    }
}

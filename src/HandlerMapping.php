<?php

namespace PhpIniAudit;

final class HandlerMapping
{
    public Location $location;
    public string $statement;
    /** @var list<string> */
    public array $extensions;
    public ?string $filesPattern;

    public function __construct(Location $location, string $statement, array $extensions, ?string $filesPattern)
    {
        $this->location = $location;
        $this->statement = $statement;
        $this->extensions = $extensions;
        $this->filesPattern = $filesPattern;
    }
}

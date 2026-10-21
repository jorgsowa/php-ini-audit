<?php

namespace PhpIniAudit;

final class Location
{
    public string $path;
    public ?int $line;

    public function __construct(string $path, ?int $line = null)
    {
        $this->path = $path;
        $this->line = $line;
    }

    public function __toString(): string
    {
        return $this->line ? "{$this->path}:{$this->line}" : $this->path;
    }
}

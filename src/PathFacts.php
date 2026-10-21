<?php

namespace PhpIniAudit;

final class PathFacts
{
    public string $path;
    public bool $exists;
    public bool $isDir = false;
    public bool $worldWritable = false;
    public bool $worldReadable = false;
    public bool $groupWritable = false;
    public bool $sticky = false;
    public ?string $writableAncestor = null;
    public bool $writableAncestorSticky = false;

    public function __construct(string $path, bool $exists)
    {
        $this->path = $path;
        $this->exists = $exists;
    }
}

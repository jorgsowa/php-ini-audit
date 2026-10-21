<?php

namespace PhpIniAudit;

final class VersionEvidence
{
    /** @var list<int> */
    public array $version;
    public string $source;
    public bool $backports;

    /** @param list<int> $version */
    public function __construct(array $version, string $source, bool $backports = false)
    {
        $this->version = $version;
        $this->source = $source;
        $this->backports = $backports;
    }

    /** @return array{int, int} */
    public function branch(): array
    {
        return [$this->version[0], $this->version[1]];
    }
}

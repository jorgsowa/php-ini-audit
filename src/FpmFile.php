<?php

namespace PhpIniAudit;

final class FpmFile
{
    public string $path;
    public string $kind = SourceKind::FPM;
    /** @var list<FpmPool> */
    public array $pools = [];
    /** @var array<string, Directive> */
    public array $globalSettings = [];
    /** @var list<ParseIssue> */
    public array $issues = [];

    public function __construct(string $path)
    {
        $this->path = $path;
    }

    /** @return list<Directive> */
    public function phpDirectives(): array
    {
        $directives = [];
        foreach ($this->pools as $pool) {
            array_push($directives, ...$pool->php);
        }
        return $directives;
    }
}

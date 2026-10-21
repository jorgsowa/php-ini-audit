<?php

namespace PhpIniAudit;

final class IniFile
{
    public string $path;
    public string $kind;
    /** @var list<Directive> */
    public array $directives = [];
    /** @var list<ParseIssue> */
    public array $issues = [];
    /** @var list<array{string, Location}> */
    public array $conditionalSections = [];

    public function __construct(string $path, string $kind)
    {
        $this->path = $path;
        $this->kind = $kind;
    }

    /** @return list<Directive> */
    public function phpDirectives(): array
    {
        return $this->directives;
    }

    /** @return list<Directive> */
    public function baseDirectives(): array
    {
        return array_values(array_filter($this->directives, static function (Directive $d): bool {
            return !Parser::isConditional($d->section);
        }));
    }
}

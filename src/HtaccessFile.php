<?php

namespace PhpIniAudit;

final class HtaccessFile
{
    public string $path;
    public string $kind = SourceKind::HTACCESS;
    /** @var list<Directive> */
    public array $directives = [];
    /** @var list<ParseIssue> */
    public array $issues = [];
    /** @var list<HandlerMapping> */
    public array $handlers = [];

    public function __construct(string $path)
    {
        $this->path = $path;
    }

    /** @return list<Directive> */
    public function phpDirectives(): array
    {
        return $this->directives;
    }
}

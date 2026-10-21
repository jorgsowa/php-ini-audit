<?php

namespace PhpIniAudit;

final class AuditResult
{
    /** @var list<Target> */
    public array $targets;
    /** @var list<Finding> */
    public array $findings;
    /** @var list<string> */
    public array $files;
    /** @var list<string> */
    public array $warnings;
    public int $rulesEvaluated;
    public bool $pathChecks;

    public function __construct(array $targets, array $findings, array $files, array $warnings, int $rulesEvaluated,
        bool $pathChecks)
    {
        $this->targets = $targets;
        $this->findings = $findings;
        $this->files = $files;
        $this->warnings = $warnings;
        $this->rulesEvaluated = $rulesEvaluated;
        $this->pathChecks = $pathChecks;
    }
}

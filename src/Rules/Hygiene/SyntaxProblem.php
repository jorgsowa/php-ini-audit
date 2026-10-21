<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\FileRule;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class SyntaxProblem extends FileRule
{
    public const ID = 'CFG-001';
    public const TITLE = 'Syntax problem in configuration file';
    public const SEVERITY = Severity::LOW;
    public const DESCRIPTION = 'Lines PHP cannot parse are ignored or stop INI parsing at that point, so later '
        . 'settings silently do not apply.';
    public const RECOMMENDATION = "Fix the reported lines; use ';' for comments.";

    public function check(FileContext $fctx): iterable
    {
        foreach ($fctx->file->issues as $issue) {
            yield new Hit($issue->message, [], null, Confidence::HIGH, $issue->location);
        }
    }
}

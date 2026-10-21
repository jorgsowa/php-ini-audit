<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\FileRule;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Severity;

final class EnvironmentValue extends FileRule
{
    public const ID = 'CFG-007';
    public const TITLE = 'Value depends on an environment variable';
    public const SEVERITY = Severity::INFO;
    public const DESCRIPTION = '${VAR} is expanded by PHP at start-up from its own environment, so a static audit '
        . 'cannot know the effective value; rules evaluated the literal text.';
    public const RECOMMENDATION = 'Check the variable in the PHP process environment, or use a literal value.';

    public function check(FileContext $fctx): iterable
    {
        $sensitive = Registry::securityDirectives();
        foreach ($fctx->file->phpDirectives() as $directive) {
            if ($directive->unresolved) {
                yield new Hit("{$directive->name} = {$directive->raw}", [$directive],
                    in_array($directive->name, $sensitive, true) ? Severity::LOW : Severity::INFO);
            }
        }
    }
}

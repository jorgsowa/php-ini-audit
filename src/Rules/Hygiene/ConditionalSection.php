<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Confidence;
use PhpIniAudit\IniFile;
use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\FileRule;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class ConditionalSection extends FileRule
{
    public const ID = 'CFG-009';
    public const TITLE = 'Conditional [PATH=]/[HOST=] section';
    public const SEVERITY = Severity::INFO;
    public const DESCRIPTION = 'Directives in [PATH=...] or [HOST=...] sections apply only to matching requests under '
        . 'CGI/FastCGI; they are audited as separate overlays.';
    public const RECOMMENDATION = 'Verify these sections still match deployed paths and hosts.';

    public function check(FileContext $fctx): iterable
    {
        $sections = $fctx->file instanceof IniFile ? $fctx->file->conditionalSections : [];
        foreach ($sections as [$section, $location]) {
            yield new Hit("[$section] overrides settings for matching requests", [], null, Confidence::HIGH,
                $location);
        }
    }
}

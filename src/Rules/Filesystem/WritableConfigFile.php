<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\FileRule;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class WritableConfigFile extends FileRule
{
    public const ID = 'FS-011';
    public const TITLE = 'Configuration file writable by other users';
    public const SEVERITY = Severity::CRITICAL;
    public const CWE = 'CWE-732';
    public const DESCRIPTION = 'Anyone who can write a PHP configuration file or its directory can enable '
        . 'auto_prepend_file, load extensions or disable protections.';
    public const RECOMMENDATION = 'Make configuration files and their directories owned by root and not writable by '
        . 'group or others.';

    public function check(FileContext $fctx): iterable
    {
        if ($fctx->paths === null) {
            return;
        }
        $facts = $fctx->paths->facts($fctx->path());
        if ($facts === null || !$facts->exists) {
            return;
        }
        if ($facts->worldWritable) {
            yield new Hit("{$fctx->path()} is world-writable");
        } elseif ($facts->writableAncestor !== null && $facts->writableAncestor !== ''
            && !$facts->writableAncestorSticky) {
            yield new Hit("{$fctx->path()} is in world-writable directory {$facts->writableAncestor}");
        } elseif ($facts->groupWritable) {
            yield new Hit("{$fctx->path()} is group-writable", [], Severity::LOW, Confidence::MEDIUM);
        }
    }
}

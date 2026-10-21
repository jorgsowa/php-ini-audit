<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Support\ConfiguredPaths;
use PhpIniAudit\Setting;
use PhpIniAudit\Severity;

final class MissingPath extends ConfigRule
{
    public const ID = 'FS-007';
    public const TITLE = 'Configured path does not exist';
    public const SEVERITY = Severity::INFO;
    public const DESCRIPTION = 'An explicitly configured path does not exist on the audited system; PHP silently '
        . 'falls back or fails at runtime, and whoever creates the path first controls it.';
    public const RECOMMENDATION = 'Create the path with the intended owner and permissions, or remove the directive.';

    public function check(Context $ctx): iterable
    {
        if ($ctx->paths === null) {
            return;
        }
        foreach (ConfiguredPaths::in($ctx) as [, $setting, $path]) {
            if ($setting instanceof Setting && !$setting->isSet()) {
                continue;
            }
            $facts = $ctx->paths->facts($path);
            if ($facts !== null && !$facts->exists
                && ($facts->writableAncestor === null || $facts->writableAncestor === '')) {
                yield new Hit("{$setting->name} path $path does not exist", [$setting]);
            }
        }
    }
}

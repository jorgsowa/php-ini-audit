<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Support\ConfiguredPaths;
use PhpIniAudit\Setting;
use PhpIniAudit\Severity;

final class WorldWritablePath extends ConfigRule
{
    public const ID = 'FS-005';
    public const TITLE = 'Security-relevant path is world-writable';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-732';
    public const DESCRIPTION = 'A path PHP loads code, certificates, sessions or logs from is writable by every local '
        . 'user, or sits in a world-writable directory where it can be created or replaced.';
    public const RECOMMENDATION = 'Make the path owned by root (or the deploy user) and not writable by others; use a '
        . 'dedicated directory instead of /tmp.';

    public function check(Context $ctx): iterable
    {
        if ($ctx->paths === null) {
            return;
        }
        foreach (ConfiguredPaths::in($ctx) as [$spec, $setting, $path]) {
            [, , $purpose, $writable] = $spec;
            if ($writable === null) {
                continue;
            }
            $facts = $ctx->paths->facts($path);
            if ($facts === null) {
                continue;
            }
            $label = "{$setting->name} path $path";
            $defaultValue = $setting instanceof Setting && !$setting->isSet();
            if ($facts->worldWritable) {
                $sticky = $facts->sticky ? ' (sticky)' : '';
                yield new Hit("$label is world-writable$sticky; $purpose", [$setting], $writable,
                    $defaultValue ? Confidence::LOW : Confidence::HIGH);
            } elseif ($facts->writableAncestor !== null && $facts->writableAncestor !== '') {
                $state = !$facts->exists ? 'does not exist' : 'exists';
                $replaceable = !$facts->writableAncestorSticky || !$facts->exists;
                if ($replaceable) {
                    yield new Hit("$label $state in world-writable {$facts->writableAncestor}; $purpose", [$setting],
                        $writable, $defaultValue ? Confidence::LOW : Confidence::MEDIUM);
                }
            }
        }
    }
}

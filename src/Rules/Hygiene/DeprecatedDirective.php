<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Directives;
use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\FileRule;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Severity;
use PhpIniAudit\SourceKind;
use PhpIniAudit\Util;

final class DeprecatedDirective extends FileRule
{
    public const ID = 'CFG-010';
    public const TITLE = 'Deprecated directive';
    public const SEVERITY = Severity::INFO;
    public const DESCRIPTION = 'Deprecated directives set to a non-default value still work but emit warnings and '
        . 'will disappear in a future release.';
    public const RECOMMENDATION = 'Plan to remove the directive; remove it now from .user.ini/.htaccess on PHP '
        . 'versions affected by CVE-2026-109619.';

    public function check(FileContext $fctx): iterable
    {
        // Per-request deprecation warnings fire before request state is initialised, a CVE-2026-109619 trigger.
        $perRequest = in_array($fctx->file->kind, [SourceKind::USER_INI, SourceKind::HTACCESS], true)
            && Registry::advisory('CVE-2026-109619')->exposes($fctx->phpVersion);
        foreach ($fctx->file->phpDirectives() as $directive) {
            $since = Directives::DEPRECATED[$directive->name] ?? null;
            if ($since === null) {
                continue;
            }
            if ($fctx->phpVersion !== null
                && Util::compare($fctx->phpVersion, Directives::versionTuple($since)) < 0) {
                continue;
            }
            if ($directive->value === Directives::default($directive->name)) {
                continue;
            }
            if ($perRequest) {
                yield new Hit("{$directive->name} is deprecated since PHP $since and its per-request warning can "
                    . 'trigger CVE-2026-109619', [$directive], Severity::MEDIUM);
            } else {
                yield new Hit("{$directive->name} is deprecated since PHP $since", [$directive]);
            }
        }
    }
}

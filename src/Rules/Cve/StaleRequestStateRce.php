<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Confidence;
use PhpIniAudit\Directives;
use PhpIniAudit\OverlayKind;
use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Setting;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class StaleRequestStateRce extends Advisory
{
    public const ID = 'CVE-2026-109619';
    public const TITLE = 'Remote code execution through stale request state';
    public const SEVERITY = Severity::CRITICAL;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-416';
    public const FIXED = ['8.2.35', '8.3.36', '8.4.27', '8.5.12'];
    public const DESCRIPTION = 'Request-owned state survives a fatal error into the next request on the same worker '
        . 'and is used before initialisation. Confirmed paths are session upload progress and, on PHP 8.5, fatal '
        . 'error backtraces; other variants remain.';
    public const RECOMMENDATION = 'Upgrade. Until then set session.upload_progress.enabled = 0 in php.ini or the FPM '
        . 'pool (not .user.ini or ini_set()), on PHP 8.5 set fatal_error_backtraces = 0, restart every worker, and '
        . 'remove deprecated settings from .user.ini/.htaccess.';

    public function exposure(Context $ctx): ?Exposure
    {
        [$progress, $late] = self::beforeRequestParsing($ctx, 'session.upload_progress.enabled');
        $paths = [];
        $evidence = [];
        if ($progress->asBool()) {
            if ($late !== null) {
                $paths[] = "session upload progress stays On because {$late->describe()} in .user.ini applies "
                    . 'after request parsing';
                $evidence[] = $late;
            } else {
                $paths[] = 'session.upload_progress.enabled is On';
                $evidence[] = $progress;
            }
        }
        $backtraces = $ctx->get('fatal_error_backtraces');
        if ($ctx->phpVersion !== null && Util::compare($ctx->phpVersion, [8, 5]) >= 0 && $backtraces->asBool()) {
            $paths[] = 'fatal_error_backtraces is On';
            $evidence[] = $backtraces;
        }
        if ($paths) {
            return new Exposure(implode('; ', $paths), $evidence);
        }
        return new Exposure('the confirmed paths are closed, but other variants remain', [$late ?? $progress],
            Confidence::MEDIUM);
    }

    /**
     * The value in force while the request body is parsed, and the .user.ini override that comes too late.
     * @return array{Setting, ?Setting}
     */
    private static function beforeRequestParsing(Context $ctx, string $name): array
    {
        $setting = $ctx->get($name);
        if ($ctx->overlayKind !== OverlayKind::USER_INI || !$ctx->config->isOverlay($setting->directive)) {
            return [$setting, null];
        }
        if ($setting->overridden) {
            $previous = $setting->overridden[count($setting->overridden) - 1];
            return [new Setting($name, $previous->value, $previous, array_slice($setting->overridden, 0, -1)),
                $setting];
        }
        return [new Setting($name, Directives::default($name)), $setting];
    }
}

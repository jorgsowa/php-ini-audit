<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class MemoryLimit extends ConfigRule
{
    public const ID = 'RES-001';
    public const TITLE = 'Unlimited or very large memory_limit';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['memory_limit'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-770';
    public const DESCRIPTION = 'memory_limit = -1 lets one request exhaust server memory.';
    public const RECOMMENDATION = 'Set memory_limit to what the application needs (typically 128M-512M).';

    private const GIB = 1073741824;

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('memory_limit');
        $size = $setting->asBytes();
        if ($size !== null && $size < 0) {
            if (Registry::advisory('CVE-2026-109618')->exposes($ctx->phpVersion)) {
                yield new Hit('memory_limit is unlimited (-1), the interim mitigation for CVE-2026-109618; '
                    . 'restore a limit after upgrading', [$setting], Severity::INFO);
            } else {
                yield new Hit('memory_limit is unlimited (-1)', [$setting]);
            }
        } elseif ($size !== null && $size > self::GIB) {
            yield new Hit("{$setting->describe()} (> 1G)", [$setting], Severity::LOW);
        }
    }
}

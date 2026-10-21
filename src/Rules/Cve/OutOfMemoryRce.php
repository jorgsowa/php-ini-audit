<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class OutOfMemoryRce extends Advisory
{
    public const ID = 'CVE-2026-109618';
    public const TITLE = 'Remote code execution after an out-of-memory error';
    public const SEVERITY = Severity::CRITICAL;
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-416';
    public const FIXED = ['8.2.35', '8.3.36', '8.4.27', '8.5.12'];
    public const DESCRIPTION = 'When an allocation fails, PHP aborts the request and leaves request memory in an '
        . 'invalid state that shutdown code still uses, so a crafted request can corrupt memory and run code '
        . '(exploited in the wild). Configuration only reduces exposure.';
    public const RECOMMENDATION = 'Upgrade. Until then set memory_limit = -1 with php_admin_value so applications '
        . 'cannot lower it, keep post_max_size at 8M (32M with uploads), and bound memory with a container or cgroup '
        . 'limit rather than RLIMIT_AS/RLIMIT_DATA.';

    private const SMALL_POST_LIMIT = 32 * 1048576;

    public function exposure(Context $ctx): ?Exposure
    {
        $memory = $ctx->get('memory_limit');
        $size = $memory->asBytes();
        if ($size !== null && $size < 0) {
            $reason = "memory_limit = -1 removes PHP's own limit, but allocation failures still reach the "
                . 'vulnerable path';
            $confidence = Confidence::MEDIUM;
        } else {
            $reason = "{$memory->describe()} lets a request run into the out-of-memory path";
            $confidence = Confidence::HIGH;
        }
        $evidence = [$memory];
        $post = $ctx->get('post_max_size');
        $postSize = $post->asBytes();
        if ($postSize !== null && ($postSize <= 0 || $postSize > self::SMALL_POST_LIMIT)) {
            $reason .= "; {$post->describe()} accepts large request bodies";
            $evidence[] = $post;
        }
        return new Exposure($reason, $evidence, $confidence);
    }
}

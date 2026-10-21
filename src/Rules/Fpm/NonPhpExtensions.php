<?php

namespace PhpIniAudit\Rules\Fpm;

use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\PoolRule;
use PhpIniAudit\Rules\Support\PhpExtensions;
use PhpIniAudit\Severity;

final class NonPhpExtensions extends PoolRule
{
    public const ID = 'FPM-002';
    public const TITLE = 'Non-PHP files executable by the pool';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-434';
    public const DESCRIPTION = 'security.limit_extensions restricts which files FPM will execute. An empty list or '
        . 'image/text extensions turn uploaded files into code.';
    public const RECOMMENDATION = 'Use security.limit_extensions = .php';

    public function check(Context $ctx): iterable
    {
        [$directive, $exts] = PhpExtensions::allowedBy($ctx->pool);
        if ($directive === null) {
            return;
        }
        if (!$exts) {
            yield new Hit('security.limit_extensions is empty: every file may be executed', [$directive]);
            return;
        }
        $extra = array_values(array_filter($exts, static function (string $e): bool {
            return !PhpExtensions::isPhp($e);
        }));
        if ($extra) {
            yield new Hit('security.limit_extensions allows ' . self::names($extra), [$directive]);
        }
    }
}

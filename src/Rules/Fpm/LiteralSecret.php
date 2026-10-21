<?php

namespace PhpIniAudit\Rules\Fpm;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\PoolRule;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class LiteralSecret extends PoolRule
{
    public const ID = 'FPM-007';
    public const TITLE = 'Secret stored in pool configuration';
    public const SEVERITY = Severity::MEDIUM;
    public const CWE = 'CWE-260';
    public const DESCRIPTION = 'Literal secrets in env[] entries end up in configuration backups and in '
        . 'phpinfo()/$_SERVER.';
    public const RECOMMENDATION = 'Reference the master environment (env[DB_PASSWORD] = $DB_PASSWORD) or use a secret '
        . 'store.';

    private const SECRET_NAME = '/pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential/i';

    public function check(Context $ctx): iterable
    {
        foreach ($ctx->pool->env as $directive) {
            if (preg_match(self::SECRET_NAME, $directive->name) && $directive->value !== ''
                && !Util::startsWith($directive->value, '$')) {
                yield new Hit("env[{$directive->name}] holds a literal value", [$directive], null,
                    Confidence::MEDIUM);
            }
        }
    }
}

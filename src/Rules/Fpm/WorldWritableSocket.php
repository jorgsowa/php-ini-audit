<?php

namespace PhpIniAudit\Rules\Fpm;

use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\PoolRule;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

final class WorldWritableSocket extends PoolRule
{
    public const ID = 'FPM-003';
    public const TITLE = 'FastCGI socket writable by every user';
    public const SEVERITY = Severity::MEDIUM;
    public const CWE = 'CWE-276';
    public const DESCRIPTION = 'A world-writable FPM socket lets any local user send FastCGI requests and run code as '
        . 'the pool user.';
    public const RECOMMENDATION = 'Use listen.mode = 0660 with listen.owner/listen.group set to the web server.';

    public function check(Context $ctx): iterable
    {
        $directive = $ctx->pool->settings['listen.mode'] ?? null;
        if ($directive === null) {
            return;
        }
        $mode = Values::parseOctal($directive->value);
        if ($mode !== null && ($mode & 0002)) {
            yield new Hit("listen.mode = {$directive->value}", [$directive]);
        }
    }
}

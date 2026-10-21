<?php

namespace PhpIniAudit\Rules\Opcache;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class NoUserIsolation extends ConfigRule
{
    public const ID = 'OPC-003';
    public const TITLE = 'OPcache does not isolate users';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['opcache.validate_permission', 'opcache.validate_root'];
    public const SAPIS = Sapis::FASTCGI;
    public const CWE = 'CWE-653';
    public const DESCRIPTION = "On shared hosting without validate_permission/validate_root, one user's scripts may "
        . "hit another user's cached files.";
    public const RECOMMENDATION = 'Enable opcache.validate_permission (and validate_root with chroot) on multi-tenant '
        . 'hosts.';

    public function check(Context $ctx): iterable
    {
        $off = array_values(array_filter(['opcache.validate_permission', 'opcache.validate_root'],
            static function (string $n) use ($ctx): bool {
                return !$ctx->on($n);
            }));
        if ($off) {
            yield new Hit(self::names($off) . ' Off', array_map([$ctx, 'get'], $off), null, Confidence::LOW);
        }
    }
}

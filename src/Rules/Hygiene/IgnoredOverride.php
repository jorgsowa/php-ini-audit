<?php

namespace PhpIniAudit\Rules\Hygiene;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Severity;

final class IgnoredOverride extends ConfigRule
{
    public const ID = 'CFG-005';
    public const TITLE = 'Per-directory override that PHP ignores';
    public const SEVERITY = Severity::LOW;
    public const DESCRIPTION = '.user.ini and .htaccess can only change PHP_INI_PERDIR/PHP_INI_ALL directives. '
        . 'Hardening attempted there for PHP_INI_SYSTEM directives (disable_functions, allow_url_fopen, expose_php, '
        . '...) does not take effect.';
    public const RECOMMENDATION = 'Move the setting to php.ini or to php_admin_value in the FPM pool / Apache vhost.';

    public function check(Context $ctx): iterable
    {
        $sensitive = Registry::securityDirectives();
        foreach ($ctx->config->ineffective as $directive) {
            yield new Hit(
                "{$directive->name} cannot be changed from {$directive->kind} and is ignored",
                [$directive],
                in_array($directive->name, $sensitive, true) ? Severity::LOW : Severity::INFO
            );
        }
    }
}

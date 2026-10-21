<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class CookieWithoutSameSite extends ConfigRule
{
    public const ID = 'SESS-007';
    public const TITLE = 'Session cookie without SameSite protection';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['session.cookie_samesite', 'session.cookie_secure'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-1275';
    public const DESCRIPTION = 'Without SameSite=Lax or Strict the session cookie accompanies cross-site requests, '
        . 'which enables CSRF.';
    public const RECOMMENDATION = 'Set session.cookie_samesite = "Lax" (or "Strict").';

    public function check(Context $ctx): iterable
    {
        if ($ctx->versionBelow(7, 3)) {
            return;
        }
        $setting = $ctx->get('session.cookie_samesite');
        $value = strtolower($setting->text());
        if ($value === '') {
            if ($setting->directive !== null
                && strtolower(trim(explode(';', $setting->directive->raw)[0])) === 'none') {
                yield new Hit('unquoted None is parsed as an empty value; write "None" or (better) "Lax"',
                    [$setting]);
            } else {
                yield new Hit('session.cookie_samesite is not set', [$setting]);
            }
        } elseif ($value === 'none') {
            $secure = $ctx->get('session.cookie_secure');
            if ($secure->asBool()) {
                yield new Hit('SameSite=None sends the cookie on cross-site requests', [$setting]);
            } else {
                yield new Hit(
                    'SameSite=None without Secure: cookie sent cross-site and rejected by modern browsers',
                    [$setting, $secure],
                    Severity::MEDIUM
                );
            }
        } elseif (!in_array($value, ['lax', 'strict'], true)) {
            yield new Hit('unrecognised SameSite value ' . Util::repr($setting->text()), [$setting]);
        }
    }
}

<?php

namespace PhpIniAudit\Rules\Database;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class StoredCredentials extends ConfigRule
{
    public const ID = 'DB-002';
    public const TITLE = 'Credentials stored in PHP configuration';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = [
        'mysqli.default_pw',
        'mysql.default_password',
        'odbc.default_pw',
        'ibase.default_password',
        'pdo_odbc.default_pw',
    ];
    public const CWE = 'CWE-260';
    public const DESCRIPTION = 'Default passwords in INI files are readable by every user that can read the '
        . 'configuration and are printed by phpinfo() and ini_get_all().';
    public const RECOMMENDATION = "Pass credentials from the application's secret storage instead.";

    private const CREDENTIAL_NAME = '/(^|[._])(pw|pass|passwd|password|secret)$/i';

    public function check(Context $ctx): iterable
    {
        foreach ($ctx->config->explicit() as $setting) {
            if ($setting->text() !== '' && (in_array($setting->name, self::DIRECTIVES, true)
                || preg_match(self::CREDENTIAL_NAME, $setting->name))) {
                yield new Hit("{$setting->name} holds a value", [$setting]);
            }
        }
    }
}

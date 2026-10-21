<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class QueryStringAsArgv extends ConfigRule
{
    public const ID = 'EXEC-011';
    public const TITLE = 'Query string exposed as $argv in web requests';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['register_argc_argv'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-88';
    public const DESCRIPTION = 'register_argc_argv = On fills $argv from the query string in web requests. Combined '
        . 'with a local file inclusion this enables the pearcmd.php remote-code-execution technique; it is On by '
        . 'default when no php.ini is loaded (e.g. official Docker images).';
    public const RECOMMENDATION = 'Set register_argc_argv = Off for web SAPIs.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('register_argc_argv');
        if ($setting->asBool()) {
            yield new Hit('register_argc_argv is On for a web SAPI', [$setting]);
        }
    }
}

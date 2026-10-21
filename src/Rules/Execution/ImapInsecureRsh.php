<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class ImapInsecureRsh extends ConfigRule
{
    public const ID = 'EXEC-012';
    public const TITLE = 'imap_open() may run rsh/ssh commands';
    public const SEVERITY = Severity::HIGH;
    public const DIRECTIVES = ['imap.enable_insecure_rsh'];
    public const CWE = 'CWE-78';
    public const DESCRIPTION = 'imap.enable_insecure_rsh lets imap_open() mailbox names inject arguments into rsh/ssh '
        . '(CVE-2018-19518).';
    public const RECOMMENDATION = 'Set imap.enable_insecure_rsh = Off.';
    public const REFERENCES = ['https://nvd.nist.gov/vuln/detail/CVE-2018-19518'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('imap.enable_insecure_rsh');
        if ($setting->asBool()) {
            yield new Hit('imap.enable_insecure_rsh is On', [$setting]);
        }
    }
}

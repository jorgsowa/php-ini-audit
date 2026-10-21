<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Severity;

final class ImapOpenCommandInjection extends Advisory
{
    public const ID = 'CVE-2018-19518';
    public const TITLE = 'imap_open() runs shell commands';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-78';
    public const FIXED = ['7.0.33', '7.1.25', '7.2.13'];
    public const DESCRIPTION = 'Before the fix, rsh/ssh mailbox names in imap_open() could inject commands; there was '
        . 'no imap.enable_insecure_rsh switch.';
    public const RECOMMENDATION = 'Upgrade and keep imap.enable_insecure_rsh = Off.';

    public function exposure(Context $ctx): ?Exposure
    {
        $directive = $ctx->loadedExtension('imap');
        return $directive !== null ? new Exposure('the imap extension is loaded', [$directive]) : null;
    }
}

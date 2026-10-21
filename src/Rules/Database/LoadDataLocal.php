<?php

namespace PhpIniAudit\Rules\Database;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class LoadDataLocal extends ConfigRule
{
    public const ID = 'DB-001';
    public const TITLE = 'MySQL LOAD DATA LOCAL enabled';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['mysqli.allow_local_infile'];
    public const CWE = 'CWE-73';
    public const DESCRIPTION = 'A malicious or spoofed MySQL server can ask the client to send any local file the PHP '
        . 'user can read.';
    public const RECOMMENDATION = 'Set mysqli.allow_local_infile = Off, or restrict mysqli.local_infile_directory.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('mysqli.allow_local_infile');
        if ($setting->asBool()) {
            yield new Hit('mysqli.allow_local_infile is On', [$setting]);
        }
    }
}

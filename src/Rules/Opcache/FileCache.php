<?php

namespace PhpIniAudit\Rules\Opcache;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class FileCache extends ConfigRule
{
    public const ID = 'OPC-001';
    public const TITLE = 'OPcache file cache enabled';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['opcache.file_cache'];
    public const CWE = 'CWE-494';
    public const DESCRIPTION = 'Compiled scripts in opcache.file_cache are executed without re-reading the source. '
        . 'Anyone who can write there (or an arbitrary-file-write bug) can plant opcodes and get code execution.';
    public const RECOMMENDATION = 'Disable the file cache, or keep it in a root-owned directory the PHP user cannot '
        . 'write except through OPcache.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('opcache.file_cache');
        if ($setting->text() !== '') {
            yield new Hit($setting->describe(), [$setting], $ctx->isWeb() ? Severity::MEDIUM : Severity::LOW);
        }
    }
}

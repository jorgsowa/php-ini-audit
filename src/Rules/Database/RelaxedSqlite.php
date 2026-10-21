<?php

namespace PhpIniAudit\Rules\Database;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class RelaxedSqlite extends ConfigRule
{
    public const ID = 'DB-003';
    public const TITLE = 'SQLite safety features relaxed';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['sqlite3.defensive', 'sqlite3.extension_dir'];
    public const CWE = 'CWE-114';
    public const DESCRIPTION = 'sqlite3.defensive = Off allows SQL to corrupt the database file; '
        . 'sqlite3.extension_dir enables SQLite3::loadExtension(), which loads native code.';
    public const RECOMMENDATION = 'Keep sqlite3.defensive = On and leave sqlite3.extension_dir unset.';

    public function check(Context $ctx): iterable
    {
        $defensive = $ctx->get('sqlite3.defensive');
        if (!$defensive->asBool()) {
            yield new Hit('sqlite3.defensive is Off', [$defensive]);
        }
        $extensionDir = $ctx->get('sqlite3.extension_dir');
        if ($extensionDir->text() !== '') {
            yield new Hit("{$extensionDir->describe()} enables loadExtension()", [$extensionDir]);
        }
    }
}

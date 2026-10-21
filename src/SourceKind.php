<?php

namespace PhpIniAudit;

final class SourceKind
{
    public const PHP_INI = 'php.ini';
    public const SCAN_DIR = 'scan-dir ini';
    public const FPM = 'php-fpm config';
    public const USER_INI = '.user.ini';
    public const HTACCESS = '.htaccess';
    public const PHPINFO = 'phpinfo()';
}

<?php

namespace PhpIniAudit;

final class OverlayKind
{
    public const SECTION = 'php.ini [PATH=]/[HOST=] section';
    public const FPM_POOL = 'php-fpm pool';
    public const USER_INI = '.user.ini';
    public const HTACCESS = '.htaccess';
}

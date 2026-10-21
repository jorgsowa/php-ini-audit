<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Setting;
use PhpIniAudit\SourceKind;

final class Base
{
    public const CATEGORIES = [
        'EXEC' => 'Code execution',
        'FS' => 'Filesystem and paths',
        'ERR' => 'Information disclosure',
        'SESS' => 'Session security',
        'RES' => 'Resource limits and DoS',
        'CGI' => 'CGI / FastCGI',
        'EXT' => 'Debug and profiling extensions',
        'OPC' => 'OPcache',
        'DB' => 'Database and credentials',
        'ENC' => 'Character encoding',
        'CFG' => 'Configuration hygiene',
        'FPM' => 'PHP-FPM pools',
        'HTA' => 'Apache .htaccess',
        'VULN' => 'PHP version support',
        'CVE' => 'Known vulnerabilities',
    ];

    public const WEB_SAPIS = ['fpm', 'cgi', 'apache2', 'litespeed', 'unknown'];
    public const FASTCGI_SAPIS = ['fpm', 'cgi', 'litespeed', 'unknown'];

    public static function overlaySet(Setting $setting): bool
    {
        return $setting->directive !== null
            && in_array($setting->directive->kind, [SourceKind::USER_INI, SourceKind::HTACCESS], true);
    }

    /** @param iterable<string> $items */
    public static function names(iterable $items): string
    {
        return implode(', ', is_array($items) ? $items : iterator_to_array($items, false));
    }
}

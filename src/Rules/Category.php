<?php

namespace PhpIniAudit\Rules;

/** Rule categories: the rule ID prefix, its display name, and the namespace holding its rules. */
final class Category
{
    public const NAMES = [
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

    public const NAMESPACES = [
        'EXEC' => 'Execution',
        'FS' => 'Filesystem',
        'ERR' => 'Disclosure',
        'SESS' => 'Session',
        'RES' => 'Resources',
        'CGI' => 'Cgi',
        'EXT' => 'Extensions',
        'OPC' => 'Opcache',
        'DB' => 'Database',
        'ENC' => 'Encoding',
        'CFG' => 'Hygiene',
        'FPM' => 'Fpm',
        'HTA' => 'Htaccess',
        'VULN' => 'Version',
        'CVE' => 'Cve',
    ];
}

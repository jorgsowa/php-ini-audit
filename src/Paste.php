<?php

namespace PhpIniAudit;

/** Audit configuration pasted as text, recognising what kind of input it is. */
final class Paste
{
    // kind => [label, path the findings point at]
    public const KINDS = [
        'phpinfo' => ['phpinfo() output', 'phpinfo()'],
        'php.ini' => ['php.ini', 'php.ini'],
        'user.ini' => ['.user.ini', '.user.ini'],
        'fpm' => ['PHP-FPM configuration', 'php-fpm.conf'],
        'htaccess' => ['.htaccess', '.htaccess'],
    ];
    private const PHPINFO = '/<td class="e">|\bLocal Value\b|^PHP Version\b|^phpinfo\(\)/m';
    private const HTACCESS = '/^[ \t]*(?:php_(?:admin_)?(?:value|flag)\s+[\w.]+\s|<(?:IfModule|FilesMatch|Files|Directory|Location)\b'
        . '|(?:AddHandler|AddType|SetHandler|RewriteEngine|RewriteRule|Options|Require|DirectoryIndex)\s)/mi';
    private const FPM = '/^[ \t]*(?:listen|pm|pm\.[\w.]+|php_(?:admin_)?(?:value|flag)\[[\w.]+\]|security\.limit_extensions|clear_env'
        . '|catch_workers_output|request_terminate_timeout|process_control_timeout|daemonize|ping\.path)[ \t]*=/m';

    public static function detect(string $text): string
    {
        if (preg_match(self::PHPINFO, $text)) {
            return 'phpinfo';
        }
        if (preg_match(self::HTACCESS, $text)) {
            return 'htaccess';
        }
        if (preg_match(self::FPM, $text)) {
            return 'fpm';
        }
        return 'php.ini';
    }

    /** @return list<int>|null */
    public static function parseVersion(string $text): ?array
    {
        $text = trim($text);
        if ($text === '') {
            return null;
        }
        if (!preg_match('/^\d+\.\d+(\.\d+)?\z/', $text)) {
            throw new \InvalidArgumentException('PHP version must look like 8.3 or 8.3.12');
        }
        return array_map('intval', explode('.', $text));
    }

    /**
     * Return the input kind (detected unless given) and the audit of the pasted text.
     * @return array{0: string, 1: AuditResult}
     */
    public static function audit(string $text, ?string $kind = null, ?Options $options = null): array
    {
        $options = $options ?? new Options();
        $options->pathChecks = false;
        if ($kind === null || $kind === '') {
            $kind = self::detect($text);
        }
        if (!isset(self::KINDS[$kind])) {
            throw new \InvalidArgumentException("unknown input kind: $kind");
        }
        if ($kind === 'phpinfo') {
            return [$kind, Phpinfo::audit($text, $options)];
        }

        $path = self::KINDS[$kind][1];
        $discovery = new Discovery();
        if ($kind === 'fpm') {
            $parsed = Parser::parseFpm($text, $path);
            $found = $parsed->pools || $parsed->globalSettings;
            $installation = new Installation('pasted PHP-FPM configuration', null);
            $installation->fpmFiles = [$path];
            $installation->sapi = 'fpm';
            $discovery->installations[] = $installation;
        } elseif ($kind === 'htaccess') {
            $parsed = Parser::parseHtaccess($text, $path);
            $found = $parsed->directives || $parsed->handlers;
            $discovery->htaccess[] = $path;
        } elseif ($kind === 'user.ini') {
            $parsed = Parser::parseIni($text, $path, SourceKind::USER_INI);
            $found = (bool) $parsed->directives;
            $discovery->userInis[] = $path;
        } else {
            $parsed = Parser::parseIni($text, $path, SourceKind::PHP_INI);
            $found = (bool) $parsed->directives;
            $discovery->installations[] = new Installation('pasted php.ini', $path);
        }
        if (!$found) {
            throw new \InvalidArgumentException('no ' . self::KINDS[$kind][0] . ' settings found in the pasted text');
        }
        $auditor = new Auditor(new FileSystem(), $options);
        // Seeding the parse cache keeps the file system out of it: nothing is read from disk.
        $auditor->parsed[$path] = $parsed;
        return [$kind, $auditor->run($discovery)];
    }
}

<?php

namespace PhpIniAudit;

/** Path predicates and POSIX path arithmetic on display paths. */
final class Paths
{
    public const WEBROOT_HINT = '#/(public_html|htdocs|httpdocs|wwwroot|www|html|public|web|webroot)(/|$)#i';
    public const WINDOWS_ABSOLUTE = '#^[A-Za-z]:[\\\\/]#';

    public static function isAbsolute(string $path): bool
    {
        return Util::startsWith($path, '/') || preg_match(self::WINDOWS_ABSOLUTE, $path) === 1;
    }

    public static function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }

    /** posixpath.normpath() */
    public static function normpath(string $path): string
    {
        if ($path === '') {
            return '.';
        }
        $initial = Util::startsWith($path, '/') ? 1 : 0;
        if ($initial && Util::startsWith($path, '//') && !Util::startsWith($path, '///')) {
            $initial = 2;
        }
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part !== '..' || (!$initial && !$parts) || ($parts && end($parts) === '..')) {
                $parts[] = $part;
            } elseif ($parts) {
                array_pop($parts);
            }
        }
        $result = str_repeat('/', $initial) . implode('/', $parts);
        return $result === '' ? '.' : $result;
    }

    /** posixpath.dirname() */
    public static function dirname(string $path): string
    {
        $head = substr($path, 0, (int) strrpos('/' . $path, '/'));
        if ($head !== '' && $head !== str_repeat('/', strlen($head))) {
            $head = rtrim($head, '/');
        }
        return $head;
    }

    /** posixpath.basename() */
    public static function basename(string $path): string
    {
        $slash = strrpos($path, '/');
        return $slash === false ? $path : substr($path, $slash + 1);
    }

    /** posixpath.join() */
    public static function join(string $path, string ...$parts): string
    {
        foreach ($parts as $part) {
            if (Util::startsWith($part, '/')) {
                $path = $part;
            } elseif ($path === '' || Util::endsWith($path, '/')) {
                $path .= $part;
            } else {
                $path .= '/' . $part;
            }
        }
        return $path;
    }

    /** posixpath.abspath() */
    public static function abspath(string $path): string
    {
        if (!Util::startsWith($path, '/')) {
            $path = self::join((string) getcwd(), $path);
        }
        return self::normpath($path);
    }

    /** posixpath.relpath() */
    public static function relpath(string $path, string $start): string
    {
        $startParts = array_values(array_filter(explode('/', self::abspath($start)), 'strlen'));
        $pathParts = array_values(array_filter(explode('/', self::abspath($path)), 'strlen'));
        $common = 0;
        while ($common < count($startParts) && $common < count($pathParts)
            && $startParts[$common] === $pathParts[$common]) {
            $common++;
        }
        $rel = array_merge(array_fill(0, count($startParts) - $common, '..'), array_slice($pathParts, $common));
        return $rel ? implode('/', $rel) : '.';
    }

    /** ntpath.join() for the drive-relative paths of Windows installations. */
    public static function ntJoin(string $path, string ...$parts): string
    {
        foreach ($parts as $part) {
            if (preg_match('#^([\\\\/]|[A-Za-z]:[\\\\/])#', $part)) {
                $path = $part;
            } elseif ($path === '' || preg_match('#[\\\\/:]$#', $path)) {
                $path .= $part;
            } else {
                $path .= '\\' . $part;
            }
        }
        return $path;
    }

    /** ntpath.dirname() */
    public static function ntDirname(string $path): string
    {
        $drive = preg_match('#^[A-Za-z]:#', $path) ? substr($path, 0, 2) : '';
        $rest = substr($path, strlen($drive));
        $cut = max((int) strrpos('/' . $rest, '/'), (int) strrpos('\\' . $rest, '\\'));
        $head = substr($rest, 0, $cut);
        $trimmed = rtrim($head, '/\\');
        return $drive . ($trimmed === '' ? $head : $trimmed);
    }

    /** join() with the host platform's separator. */
    public static function osJoin(string $path, string ...$parts): string
    {
        return self::isWindows() ? self::ntJoin($path, ...$parts) : self::join($path, ...$parts);
    }

    /** dirname() with the host platform's separator. */
    public static function osDirname(string $path): string
    {
        return self::isWindows() ? self::ntDirname($path) : self::dirname($path);
    }

    /** basename() with the host platform's separator. */
    public static function osBasename(string $path): string
    {
        if (!self::isWindows()) {
            return self::basename($path);
        }
        $rest = preg_replace('#^[A-Za-z]:#', '', $path);
        $cut = max((int) strrpos('/' . $rest, '/'), (int) strrpos('\\' . $rest, '\\'));
        return substr($rest, $cut);
    }
}

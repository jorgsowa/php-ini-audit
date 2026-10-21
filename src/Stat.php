<?php

namespace PhpIniAudit;

/** File type and permission bits of stat()'s mode. */
final class Stat
{
    public const S_IFMT = 0170000;
    public const S_IFDIR = 0040000;
    public const S_IFREG = 0100000;
    public const S_IFLNK = 0120000;
    public const S_ISVTX = 01000;
    public const S_IWGRP = 0020;
    public const S_IROTH = 0004;
    public const S_IWOTH = 0002;

    public static function isDir(int $mode): bool
    {
        return ($mode & self::S_IFMT) === self::S_IFDIR;
    }

    public static function isReg(int $mode): bool
    {
        return ($mode & self::S_IFMT) === self::S_IFREG;
    }

    public static function isLink(int $mode): bool
    {
        return ($mode & self::S_IFMT) === self::S_IFLNK;
    }
}

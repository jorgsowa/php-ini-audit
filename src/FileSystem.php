<?php

namespace PhpIniAudit;

/**
 * Read-only filesystem access, optionally confined to an alternative root (container image, chroot, mount).
 * Paths handed in and out are *display* paths: absolute paths as seen inside the audited system.
 */
final class FileSystem
{
    public const MAX_FILE_BYTES = 4 * 1024 * 1024;
    public const MAX_SYMLINKS = 40;
    public const SKIP_DIRS = ['.git', '.hg', '.svn', 'node_modules'];

    private const REPLACEMENT = "\xEF\xBF\xBD";
    // Well-formed multibyte sequences are skipped; maximal ill-formed subparts become one U+FFFD.
    private const INVALID_UTF8 = '/(?:[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}'
        . '|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}'
        . '|\xF4[\x80-\x8F][\x80-\xBF]{2})(*SKIP)(*FAIL)'
        . '|\xE0[\xA0-\xBF]?|[\xE1-\xEC\xEE\xEF][\x80-\xBF]?|\xED[\x80-\x9F]?|\xF0(?:[\x90-\xBF][\x80-\xBF]?)?'
        . '|[\xF1-\xF3](?:[\x80-\xBF][\x80-\xBF]?)?|\xF4(?:[\x80-\x8F][\x80-\xBF]?)?|[\x80-\xFF]/';

    public ?string $root;
    public bool $confined;

    public function __construct(?string $root = null)
    {
        $this->root = $root !== null && $root !== '' ? self::hostAbspath($root) : null;
        $this->confined = $this->root !== null || !Paths::isWindows();
    }

    private static function hostAbspath(string $path): string
    {
        if (!Paths::isWindows()) {
            return Paths::abspath($path);
        }
        $real = realpath($path);
        return $real === false ? $path : $real;
    }

    public function toHost(string $path): string
    {
        if ($this->root === null) {
            return $path;
        }
        return Paths::osJoin($this->root, ltrim($path, '/\\'));
    }

    public function toDisplay(string $hostPath): string
    {
        if ($this->root === null) {
            return $hostPath;
        }
        $rel = Paths::relpath($hostPath, $this->root);
        if ($rel === '.') {
            return '/';
        }
        if (Util::startsWith($rel, '..')) {
            throw new \InvalidArgumentException("$hostPath is outside the root {$this->root}");
        }
        return '/' . str_replace(DIRECTORY_SEPARATOR, '/', $rel);
    }

    /** Resolve symlinks without ever leaving the root; absolute link targets are re-anchored at the root. */
    public function resolve(string $path): string
    {
        if (!$this->confined) {
            $real = realpath($path);
            return $real === false ? $path : $real;
        }
        $pending = self::parts($path);
        $resolved = [];
        $hops = 0;
        while ($pending) {
            $part = array_shift($pending);
            if ($part === '.') {
                continue;
            }
            if ($part === '..') {
                array_pop($resolved);
                continue;
            }
            $candidate = '/' . implode('/', array_merge($resolved, [$part]));
            $info = @lstat($this->toHost($candidate));
            if ($info === false) {
                $resolved[] = $part;
                foreach ($pending as $rest) {
                    if ($rest !== '.') {
                        $resolved[] = $rest;
                    }
                }
                return Paths::normpath('/' . implode('/', $resolved));
            }
            if (Stat::isLink($info['mode'])) {
                $hops++;
                if ($hops > self::MAX_SYMLINKS) {
                    throw new ReadError("too many symbolic links resolving $path");
                }
                $target = @readlink($this->toHost($candidate));
                if ($target === false) {
                    $target = '';
                }
                if (Util::startsWith($target, '/')) {
                    $resolved = [];
                }
                $pending = array_merge(self::parts($target), $pending);
                continue;
            }
            $resolved[] = $part;
        }
        return '/' . implode('/', $resolved);
    }

    /** @return list<string> */
    private static function parts(string $path): array
    {
        return array_values(array_filter(explode('/', $path), 'strlen'));
    }

    /** @return array<string, int>|null */
    public function stat(string $path): ?array
    {
        try {
            $info = @lstat($this->toHost($this->resolve($path)));
        } catch (ReadError $exception) {
            return null;
        }
        return $info === false ? null : $info;
    }

    /** @return array<string, int>|null */
    public function lstat(string $path): ?array
    {
        $info = @lstat($this->toHost($path));
        return $info === false ? null : $info;
    }

    public function isFile(string $path): bool
    {
        $info = $this->stat($path);
        return $info !== null && Stat::isReg($info['mode']);
    }

    public function isDir(string $path): bool
    {
        $info = $this->stat($path);
        return $info !== null && Stat::isDir($info['mode']);
    }

    /** @return list<string> */
    public function listdir(string $path): array
    {
        try {
            $host = $this->toHost($this->resolve($path));
        } catch (ReadError $exception) {
            return [];
        }
        return self::entries($host) ?? [];
    }

    /** @return list<string>|null */
    private static function entries(string $host): ?array
    {
        $info = @stat($host);
        if ($info === false || !Stat::isDir($info['mode'])) {
            return null;
        }
        $names = @scandir($host, SCANDIR_SORT_NONE);
        if ($names === false) {
            return null;
        }
        $names = array_values(array_diff(array_map('strval', $names), ['.', '..']));
        sort($names, SORT_STRING);
        return $names;
    }

    /** @return list<string> */
    public function glob(string $pattern): array
    {
        if ($this->root === null) {
            $matches = glob($pattern);
        } else {
            $escaped = preg_replace('/[\\\\*?\[]/', '\\\\$0', $this->root);
            $matches = glob(Paths::osJoin($escaped, ltrim($pattern, '/')));
        }
        $display = [];
        foreach ($matches ?: [] as $match) {
            if (!self::matchesDotEntry($pattern, $match)) {
                $display[] = $this->toDisplay($match);
            }
        }
        $display = array_values(array_unique($display));
        sort($display, SORT_STRING);
        return $display;
    }

    /** A wildcard component never matches "." or "..", unlike libc glob(). */
    private static function matchesDotEntry(string $pattern, string $match): bool
    {
        $patternParts = self::parts($pattern);
        $matchParts = array_slice(self::parts($match), -count($patternParts) ?: PHP_INT_MAX);
        foreach ($patternParts as $index => $part) {
            if (strpbrk($part, '*?[') !== false && in_array($matchParts[$index] ?? '', ['.', '..'], true)) {
                return true;
            }
        }
        return false;
    }

    public function readText(string $path): string
    {
        $host = $this->toHost($this->resolve($path));
        $error = self::openError($host);
        if ($error !== null) {
            throw new ReadError("cannot open $path: $error");
        }
        $info = @lstat($host);
        if (!Stat::isReg($info['mode'])) {
            throw new ReadError("$path is not a regular file");
        }
        if ($info['size'] > self::MAX_FILE_BYTES) {
            throw new ReadError("$path is larger than " . self::MAX_FILE_BYTES . ' bytes');
        }
        $handle = @fopen($host, 'rb');
        if ($handle === false) {
            throw new ReadError("cannot open $path: Permission denied");
        }
        try {
            $opened = fstat($handle);
            if ($opened === false || !Stat::isReg($opened['mode'])) {
                throw new ReadError("$path is not a regular file");
            }
            if ($opened['size'] > self::MAX_FILE_BYTES) {
                throw new ReadError("$path is larger than " . self::MAX_FILE_BYTES . ' bytes');
            }
            $data = '';
            $remaining = self::MAX_FILE_BYTES + 1;
            while ($remaining > 0) {
                $chunk = fread($handle, min(65536, $remaining));
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $data .= $chunk;
                $remaining -= strlen($chunk);
            }
        } finally {
            fclose($handle);
        }
        if (strlen($data) > self::MAX_FILE_BYTES) {
            throw new ReadError("$path is larger than " . self::MAX_FILE_BYTES . ' bytes');
        }
        if (strpos($data, "\x00") !== false) {
            throw new ReadError("$path contains binary data");
        }
        if (!preg_match('//u', $data)) {
            $data = (string) preg_replace(self::INVALID_UTF8, self::REPLACEMENT, $data);
        }
        return (string) preg_replace('/^(?:\xEF\xBB\xBF)+/', '', $data);
    }

    /** The strerror() an O_RDONLY|O_NOFOLLOW open of $host would fail with, or null when it would succeed. */
    private static function openError(string $host): ?string
    {
        clearstatcache(true, $host);
        $info = @lstat($host);
        if ($info === false) {
            $ancestor = $host;
            while (($parent = Paths::osDirname($ancestor)) !== $ancestor) {
                $ancestor = $parent;
                $parentInfo = @lstat($ancestor);
                if ($parentInfo === false) {
                    continue;
                }
                if (Stat::isLink($parentInfo['mode'])) {
                    $parentInfo = @stat($ancestor);
                    if ($parentInfo === false) {
                        continue;
                    }
                }
                if (!Stat::isDir($parentInfo['mode'])) {
                    return 'Not a directory';
                }
                if (!Paths::isWindows() && !is_executable($ancestor)) {
                    return 'Permission denied';
                }
                break;
            }
            return 'No such file or directory';
        }
        if (Stat::isLink($info['mode'])) {
            return 'Too many levels of symbolic links';
        }
        if (!is_readable($host)) {
            return 'Permission denied';
        }
        return null;
    }

    /**
     * Yield files below top without following directory symlinks.
     * @return \Generator<int, string>
     */
    public function walk(string $top, int $maxDepth = 12, int $maxFiles = 100000): \Generator
    {
        $hostTop = $this->toHost($this->resolve($top));
        $baseDepth = substr_count(rtrim($hostTop, DIRECTORY_SEPARATOR), DIRECTORY_SEPARATOR);
        $seen = 0;
        $stack = [$hostTop];
        while ($stack) {
            $dirpath = array_pop($stack);
            $names = self::entries($dirpath);
            if ($names === null) {
                continue;
            }
            $dirnames = [];
            $filenames = [];
            foreach ($names as $name) {
                if (is_dir(Paths::osJoin($dirpath, $name))) {
                    $dirnames[] = $name;
                } else {
                    $filenames[] = $name;
                }
            }
            $depth = substr_count(rtrim($dirpath, DIRECTORY_SEPARATOR), DIRECTORY_SEPARATOR) - $baseDepth;
            $subdirs = [];
            if ($depth < $maxDepth) {
                foreach ($dirnames as $name) {
                    $child = Paths::osJoin($dirpath, $name);
                    if (!in_array($name, self::SKIP_DIRS, true) && !is_link($child)) {
                        $subdirs[] = $child;
                    }
                }
            }
            foreach ($filenames as $name) {
                $seen++;
                if ($seen > $maxFiles) {
                    return;
                }
                yield $this->toDisplay(Paths::osJoin($dirpath, $name));
            }
            foreach (array_reverse($subdirs) as $child) {
                $stack[] = $child;
            }
        }
    }
}

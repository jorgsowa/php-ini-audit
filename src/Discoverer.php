<?php

namespace PhpIniAudit;

/** Locate PHP configuration files on a system or below user-supplied paths. */
final class Discoverer
{
    // Locations of php.ini across distributions, packagers and bundles.
    public const POSIX_INI_PATTERNS = [
        '/etc/php.ini',
        '/etc/php/php.ini',
        '/etc/php/*/*/php.ini',
        '/etc/php*/php.ini',
        '/etc/php*/*/php.ini',
        '/etc/opt/remi/php*/php.ini',
        '/usr/local/etc/php.ini',
        '/usr/local/etc/php/php.ini',
        '/usr/local/etc/php/*/php.ini',
        '/usr/local/lib/php.ini',
        '/usr/local/php*/lib/php.ini',
        '/usr/local/zend/etc/php.ini',
        '/opt/homebrew/etc/php/*/php.ini',
        '/opt/cpanel/ea-php*/root/etc/php.ini',
        '/opt/plesk/php/*/etc/php.ini',
        '/opt/alt/php*/etc/php.ini',
        '/opt/lampp/etc/php.ini',
        '/opt/bitnami/php/etc/php.ini',
        '/Applications/XAMPP/xamppfiles/etc/php.ini',
        '/Applications/MAMP/bin/php/php*/conf/php.ini',
    ];
    public const WINDOWS_INI_PATTERNS = [
        'C:/php/php.ini',
        'C:/php*/php.ini',
        'C:/tools/php*/php.ini',
        'C:/xampp/php/php.ini',
        'C:/wamp64/bin/php/php*/php.ini',
        'C:/wamp/bin/php/php*/php.ini',
        'C:/laragon/bin/php/*/php.ini',
        'C:/Program Files/PHP/*/php.ini',
    ];
    public const SCAN_DIR_NAMES = ['conf.d', 'php.d'];
    public const POOL_DIR_NAMES = ['pool.d', 'php-fpm.d'];
    public const TEMPLATE_NAMES = ['php.ini-production', 'php.ini-development'];
    // Packagers that keep extension ini files outside the php.ini directory.
    public const SCAN_DIR_OVERRIDES = [
        '/etc/php.ini' => ['/etc/php.d'],
        '/usr/local/etc/php.ini' => ['/usr/local/etc/php'],
    ];
    private const SAPI_DIRS = [
        'cli' => 'cli',
        'phpdbg' => 'cli',
        'fpm' => 'fpm',
        'php-fpm' => 'fpm',
        'apache2' => 'apache2',
        'apache' => 'apache2',
        'cgi' => 'cgi',
        'litespeed' => 'litespeed',
        'lsapi' => 'litespeed',
        'embed' => 'embed',
    ];
    private const VERSION = '#(?:^|/)(?:ea-)?php[-_/]?(\d)(?:\.?(\d{1,2}))?(?=[/.\-_]|$)#';

    public FileSystem $fs;

    public function __construct(FileSystem $fs)
    {
        $this->fs = $fs;
    }

    public static function detectSapi(string $path): string
    {
        foreach (array_reverse(explode('/', str_replace('\\', '/', $path))) as $part) {
            $lower = strtolower($part);
            if (array_key_exists($lower, self::SAPI_DIRS)) {
                return self::SAPI_DIRS[$lower];
            }
        }
        return 'unknown';
    }

    /** @return array{int, int}|null */
    public static function detectVersion(string $path): ?array
    {
        if (!preg_match(self::VERSION, str_replace('\\', '/', $path), $match)) {
            return null;
        }
        $major = (int) $match[1];
        if ($major < 4) {
            return null;
        }
        if (($match[2] ?? '') !== '') {
            return [$major, (int) $match[2]];
        }
        return null;
    }

    public static function looksLikeFpm(string $path): bool
    {
        $parts = explode('/', str_replace('\\', '/', $path));
        $name = array_pop($parts);
        return in_array($name, ['php-fpm.conf', 'www.conf'], true)
            || array_intersect($parts, self::POOL_DIR_NAMES)
            || Util::contains(strtolower($path), 'fpm');
    }

    /**
     * PHP reads *.ini from a scan dir in alphabetical order.
     * @return list<string>
     */
    public function scanFilesIn(string $directory): array
    {
        $files = [];
        foreach ($this->fs->listdir($directory) as $name) {
            $path = Paths::join($directory, $name);
            if (Util::endsWith($name, '.ini') && $this->fs->isFile($path)) {
                $files[] = $path;
            }
        }
        return $files;
    }

    private function join(string $path, string ...$parts): string
    {
        return Util::startsWith($path, '/') ? Paths::join($path, ...$parts) : Paths::osJoin($path, ...$parts);
    }

    private function dirname(string $path): string
    {
        return Util::startsWith($path, '/') ? Paths::dirname($path) : Paths::osDirname($path);
    }

    /** @param list<string>|null $scanDirs */
    public function build(?string $ini, string $directory, ?array $scanDirs = null): Installation
    {
        $hasIni = $ini !== null && $ini !== '';
        if ($scanDirs === null) {
            $scanDirs = self::SCAN_DIR_OVERRIDES[$ini ?? ''] ?? [];
            foreach (self::SCAN_DIR_NAMES as $name) {
                $scanDirs[] = $this->join($directory, $name);
            }
            $scanDirs = array_values(array_filter(array_values(array_unique($scanDirs)), function (string $d): bool {
                return $this->fs->isDir($d);
            }));
        }
        $scanFiles = [];
        foreach ($scanDirs as $scanDir) {
            foreach ($this->scanFilesIn($scanDir) as $file) {
                if ($file !== $ini) {
                    $scanFiles[] = $file;
                }
            }
        }
        $reference = $hasIni ? $ini : $directory;
        $sapi = self::detectSapi($reference);
        $fpmFiles = [];
        if ($sapi === 'fpm' || $sapi === 'unknown') {
            $parent = $this->dirname($directory);
            foreach ([$directory, $parent] as $base) {
                $conf = $this->join($base, 'php-fpm.conf');
                if ($this->fs->isFile($conf) && !in_array($conf, $fpmFiles, true)) {
                    $fpmFiles[] = $conf;
                }
                foreach (self::POOL_DIR_NAMES as $name) {
                    $poolDir = $this->join($base, $name);
                    if (!$this->fs->isDir($poolDir)) {
                        continue;
                    }
                    foreach ($this->fs->listdir($poolDir) as $entry) {
                        $candidate = $this->join($poolDir, $entry);
                        if (Util::endsWith($entry, '.conf') && $this->fs->isFile($candidate)
                            && !in_array($candidate, $fpmFiles, true)) {
                            $fpmFiles[] = $candidate;
                        }
                    }
                }
            }
        }
        $installation = new Installation($hasIni ? $ini : "$directory (no php.ini)", $ini);
        $installation->scanFiles = $scanFiles;
        $installation->scanDirs = $scanDirs;
        $installation->fpmFiles = $fpmFiles;
        $installation->sapi = $sapi;
        $installation->phpVersion = self::detectVersion($reference);
        return $installation;
    }

    public function system(): Discovery
    {
        $result = new Discovery();
        $patterns = self::POSIX_INI_PATTERNS;
        if (Paths::isWindows() && $this->fs->root === null) {
            $patterns = self::WINDOWS_INI_PATTERNS;
        }
        $seen = [];
        $candidateDirs = [];
        foreach ($patterns as $pattern) {
            foreach ($this->fs->glob($this->dirname($pattern)) as $directory) {
                if (!in_array($directory, $candidateDirs, true) && $this->fs->isDir($directory)) {
                    $candidateDirs[] = $directory;
                }
            }
        }
        foreach ($candidateDirs as $directory) {
            $ini = $this->join($directory, 'php.ini');
            if ($this->fs->isFile($ini)) {
                $key = $this->fs->resolve($ini);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $result->installations[] = $this->build($ini, $directory);
                continue;
            }
            $templates = array_values(array_filter(self::TEMPLATE_NAMES, function (string $t) use ($directory): bool {
                return $this->fs->isFile($this->join($directory, $t));
            }));
            $hasScanDir = false;
            foreach (self::SCAN_DIR_NAMES as $name) {
                if ($this->fs->isDir($this->join($directory, $name))) {
                    $hasScanDir = true;
                    break;
                }
            }
            if ($templates || ($hasScanDir && Util::contains(strtolower($directory), 'php'))) {
                $key = $this->fs->resolve($directory);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $installation = $this->build(null, $directory);
                $reason = "no php.ini in $directory";
                if ($templates) {
                    $reason .= ' (' . implode(', ', $templates) . ' present but not loaded)';
                }
                $installation->defaultsReason = $reason;
                $result->installations[] = $installation;
            }
        }
        return $result;
    }

    /** @param list<string> $paths */
    public function paths(array $paths, int $maxDepth = 12): Discovery
    {
        $result = new Discovery();
        $looseIni = [];
        $looseFpm = [];
        $consumed = [];

        $classify = function (string $path) use ($result, &$looseIni, &$looseFpm, &$consumed): void {
            $name = Paths::osBasename($path);
            if ($name === '.user.ini') {
                $result->userInis[] = $path;
            } elseif ($name === '.htaccess') {
                $result->htaccess[] = $path;
            } elseif ($name === 'php.ini' || Util::endsWith($name, 'php.ini')) {
                $installation = $this->build($path, $this->dirname($path));
                $result->installations[] = $installation;
                foreach (array_merge($installation->scanFiles, $installation->fpmFiles) as $file) {
                    $consumed[$file] = true;
                }
            } elseif (Util::endsWith($name, '.ini')) {
                $looseIni[$this->dirname($path)][] = $path;
            } elseif (Util::endsWith($name, '.conf') && self::looksLikeFpm($path)) {
                $looseFpm[] = $path;
            }
        };

        foreach ($paths as $path) {
            if ($this->fs->isDir($path)) {
                foreach ($this->fs->walk($path, $maxDepth) as $found) {
                    $name = Paths::osBasename($found);
                    if (in_array($name, ['.user.ini', '.htaccess'], true) || Util::endsWith($name, '.ini')) {
                        $classify($found);
                    } elseif (Util::endsWith($name, '.conf') && self::looksLikeFpm($found)) {
                        $classify($found);
                    }
                }
            } elseif ($this->fs->isFile($path)) {
                $classify($path);
                if (Util::endsWith($path, '.conf') && !in_array($path, $looseFpm, true)) {
                    $looseFpm[] = $path;
                }
            } else {
                $result->warnings[] = "$path: not found or not readable";
            }
        }

        ksort($looseIni, SORT_STRING);
        foreach ($looseIni as $directory => $files) {
            $directory = (string) $directory;
            $remaining = array_values(array_filter($files, static function (string $f) use ($consumed): bool {
                return !isset($consumed[$f]);
            }));
            if ($remaining) {
                sort($remaining, SORT_STRING);
                $installation = new Installation("$directory/*.ini", null);
                $installation->scanFiles = $remaining;
                $installation->scanDirs = [$directory];
                $installation->sapi = self::detectSapi($directory);
                $installation->phpVersion = self::detectVersion($directory);
                $result->installations[] = $installation;
            }
        }
        $pools = array_values(array_filter($looseFpm, static function (string $f) use ($consumed): bool {
            return !isset($consumed[$f]);
        }));
        if ($pools) {
            $installation = new Installation('php-fpm configuration', null);
            $installation->fpmFiles = $pools;
            $installation->sapi = 'fpm';
            $installation->phpVersion = self::detectVersion($pools[0]);
            $result->installations[] = $installation;
        }
        return $result;
    }
}

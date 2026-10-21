<?php

namespace PhpIniAudit;

/** Where the PHP version of an installation comes from, and how evidence is ranked. */
final class Versions
{
    public const HEADER_PATTERNS = [
        '/usr/local/include/php/main/php_version.h',
        '/usr/include/php/main/php_version.h',
        '/usr/include/php/*/main/php_version.h',
        '/usr/include/php*/main/php_version.h',
        '/opt/remi/php*/root/usr/include/php/main/php_version.h',
        '/opt/cpanel/ea-php*/root/usr/include/php/main/php_version.h',
        '/opt/plesk/php/*/include/php/main/php_version.h',
        '/opt/homebrew/opt/php*/include/php/main/php_version.h',
        '/usr/local/opt/php*/include/php/main/php_version.h',
    ];
    public const DPKG_STATUS = '/var/lib/dpkg/status';
    public const APK_INSTALLED = '/lib/apk/db/installed';
    // Homebrew links the active keg under opt/; the Cellar may also hold outdated kegs.
    public const HOMEBREW_LINKS = ['/opt/homebrew/opt/php*', '/usr/local/opt/php*'];

    public const HEADER_VERSION = '/^#define\s+PHP_VERSION\s+"(\d+)\.(\d+)\.(\d+)/m';
    public const UPSTREAM = '/^(?:\d+:)?(\d+)\.(\d+)\.(\d+)/';
    public const DPKG_PACKAGE = '/^(?:php(\d)\.(\d+)-(?:common|cli|fpm|cgi)|libapache2-mod-php(\d)\.(\d+))$/';
    public const APK_PACKAGE = '/^php(\d)(\d)(?:-common|-fpm|-cgi|-cli)?$/';

    /** @param list<int>|null $version */
    public static function formatVersion(?array $version): string
    {
        return $version ? implode('.', $version) : 'unknown';
    }

    /** @return list<int> */
    public static function parseVersion(string $text): array
    {
        $version = [];
        foreach (explode('.', $text) as $part) {
            $digits = str_replace('_', '', trim($part));
            if (!preg_match('/^[+-]?\d+(?:_\d+)*$/D', trim($part))) {
                throw new \InvalidArgumentException("invalid literal for int() with base 10: " . Util::repr($part));
            }
            $version[] = (int) $digits;
        }
        return $version;
    }

    /**
     * Choose the evidence for one installation; ambiguous branches resolve only by shared path prefix.
     * @param list<VersionEvidence> $evidence
     * @param array{int, int}|null $branch
     */
    public static function pick(array $evidence, ?array $branch, ?string $near = null): ?VersionEvidence
    {
        $candidates = array_values(array_filter($evidence, static function (VersionEvidence $e) use ($branch): bool {
            return $branch === null || $e->branch() === array_values($branch);
        }));
        if (!$candidates) {
            return null;
        }
        $distinct = [];
        foreach ($candidates as $candidate) {
            $distinct[implode('.', $candidate->version)] = true;
        }
        if (count($distinct) === 1) {
            foreach ($candidates as $candidate) {
                if (!$candidate->backports) {
                    return $candidate;
                }
            }
            return $candidates[0];
        }
        if ($near !== null && $near !== '') {
            $shared = static function (VersionEvidence $e) use ($near): int {
                return self::commonPrefixLength(explode(' ', $e->source, 2)[0], $near);
            };
            $best = $candidates[0];
            foreach ($candidates as $candidate) {
                if ($shared($candidate) > $shared($best)) {
                    $best = $candidate;
                }
            }
            if ($shared($best) > strlen('/opt/')) {
                return $best;
            }
        }
        return null;
    }

    /** Length in characters of the common prefix of two strings. */
    private static function commonPrefixLength(string $a, string $b): int
    {
        $length = 0;
        $limit = min(strlen($a), strlen($b));
        while ($length < $limit && $a[$length] === $b[$length]) {
            $length++;
        }
        $continuation = static function (string $s, int $i): bool {
            return $i < strlen($s) && (ord($s[$i]) & 0xC0) === 0x80;
        };
        while ($length > 0 && ($continuation($a, $length) || $continuation($b, $length))) {
            $length--;
        }
        return preg_match_all('/[^\x80-\xBF]/', substr($a, 0, $length));
    }
}

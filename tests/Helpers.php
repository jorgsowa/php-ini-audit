<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Auditor;
use PhpIniAudit\AuditResult;
use PhpIniAudit\Cli;
use PhpIniAudit\Discoverer;
use PhpIniAudit\FileSystem;
use PhpIniAudit\Finding;
use PhpIniAudit\Options;

final class Helpers
{
    public const FIXTURES = __DIR__ . '/fixtures';

    /**
     * Audit a php.ini given as text, plus optional extra files relative to its directory.
     * $options maps Options property names (camelCase, e.g. 'phpVersion') to values.
     *
     * @param array<string, string> $files
     * @param array<string, mixed> $options
     */
    public static function auditIni(string $text, array $files = [], array $options = []): AuditResult
    {
        $tmp = self::tempDir();
        try {
            $ini = $tmp . '/php.ini';
            file_put_contents($ini, $text);
            foreach ($files as $name => $content) {
                self::writeFile($tmp . '/' . $name, $content);
            }
            $fs = new FileSystem();
            $discovery = (new Discoverer($fs))->paths([$ini]);
            $options += ['pathChecks' => false, 'sapi' => 'fpm'];
            return (new Auditor($fs, self::options($options)))->run($discovery);
        } finally {
            self::removeTree($tmp);
        }
    }

    /** @return array{int, string, string} exit code, stdout, stderr */
    public static function runCli(string ...$argv): array
    {
        return CaptureFilter::run(static function () use ($argv): int {
            return Cli::main($argv);
        });
    }

    /** @param array<string, mixed> $values */
    public static function options(array $values = []): Options
    {
        $options = new Options();
        foreach ($values as $name => $value) {
            if (!property_exists($options, $name)) {
                throw new \InvalidArgumentException("unknown option $name");
            }
            $options->$name = $value;
        }
        return $options;
    }

    /** @return list<string> sorted, unique rule IDs */
    public static function ruleIds(AuditResult $result): array
    {
        $ids = array_values(array_unique(array_map(static function (Finding $f): string {
            return $f->ruleId;
        }, $result->findings)));
        sort($ids);
        return $ids;
    }

    /** @return list<Finding> */
    public static function findingsFor(AuditResult $result, string $ruleId): array
    {
        return array_values(array_filter($result->findings, static function (Finding $f) use ($ruleId): bool {
            return $f->ruleId === $ruleId;
        }));
    }

    public static function tempDir(): string
    {
        $base = rtrim(sys_get_temp_dir(), '/\\');
        for ($i = 0; $i < 100; $i++) {
            $dir = $base . '/php-ini-audit-' . bin2hex(random_bytes(6));
            if (@mkdir($dir, 0700)) {
                return realpath($dir) ?: $dir;
            }
        }
        throw new \RuntimeException('cannot create temporary directory');
    }

    /** Write a file, creating parent directories. */
    public static function writeFile(string $path, string $content): void
    {
        $parent = dirname($path);
        if (!is_dir($parent)) {
            mkdir($parent, 0777, true);
        }
        file_put_contents($path, $content);
    }

    public static function removeTree(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            @chmod($path, 0600);
            unlink($path);
            return;
        }
        if (!is_dir($path)) {
            return;
        }
        @chmod($path, 0700);
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                self::removeTree($path . '/' . $entry);
            }
        }
        rmdir($path);
    }
}

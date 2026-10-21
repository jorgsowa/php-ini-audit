<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Auditor;
use PhpIniAudit\Directives;
use PhpIniAudit\Discoverer;
use PhpIniAudit\FileSystem;
use PhpIniAudit\Target;
use PhpIniAudit\Util;
use PhpIniAudit\Values;
use PHPUnit\Framework\TestCase;

/**
 * Scan the exported filesystem of real PHP images and compare with what php-fpm inside reports.
 * Opt-in because it pulls images: PHP_INI_AUDIT_DOCKER=1 vendor/bin/phpunit tests/DockerImagesTest.php
 */
final class DockerImagesTest extends TestCase
{
    private const EXTRACT = ['etc/', 'usr/local/etc/', 'usr/local/include/php/main/', 'usr/include/php',
        'var/lib/dpkg/status', 'lib/apk/db/installed'];
    private const APT = 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq'
        . ' --no-install-recommends';
    private const TIMEOUT = 600;
    private const MAX_FILE = 4 * 1024 * 1024;

    /** @var list<string> */
    private array $roots = [];

    /** @return array<string, list<string>> name => [image, setup command, php-fpm binary, target that php-fpm loads] */
    private static function images(): array
    {
        return [
            'official-defaults' => ['php:8.3-fpm-alpine', 'true', 'php-fpm', '/usr/local/etc/php (no php.ini)'],
            'official-production' => [
                'php:8.3-fpm-alpine',
                'cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini',
                'php-fpm',
                '/usr/local/etc/php/php.ini',
            ],
            'alpine-packages' => [
                'alpine:3.20',
                'apk add --no-cache php83 php83-fpm php83-opcache php83-session',
                'php-fpm83',
                '/etc/php83/php.ini',
            ],
            'debian-packages' => ['debian:bookworm-slim', self::APT . ' php8.2-fpm', 'php-fpm8.2',
                '/etc/php/8.2/fpm/php.ini'],
        ];
    }

    private static function enabled(): bool
    {
        if ((string) getenv('PHP_INI_AUDIT_DOCKER') === '') {
            return false;
        }
        foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $dir) {
            if ($dir !== '' && is_file("$dir/docker") && is_executable("$dir/docker")) {
                return true;
            }
        }
        return false;
    }

    protected function setUp(): void
    {
        if (!self::enabled()) {
            $this->markTestSkipped('set PHP_INI_AUDIT_DOCKER=1 (needs docker) to scan real images');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->roots as $root) {
            Helpers::removeTree($root);
        }
        $this->roots = [];
    }

    /**
     * Run docker with the given arguments and return its stdout; throws on failure or timeout.
     *
     * @param list<string> $args
     */
    private static function docker(array $args, int $timeout = self::TIMEOUT): string
    {
        $process = proc_open(array_merge(['docker'], $args), [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes);
        if (!is_resource($process)) {
            throw new \RuntimeException('cannot run docker');
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $output = [1 => '', 2 => ''];
        $open = [1 => $pipes[1], 2 => $pipes[2]];
        $deadline = microtime(true) + $timeout;
        while ($open) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                proc_terminate($process, 9);
                proc_close($process);
                throw new \RuntimeException('docker ' . implode(' ', $args) . " timed out after {$timeout}s");
            }
            $read = array_values($open);
            $write = $except = null;
            if (stream_select($read, $write, $except, (int) $remaining, 200000) === false) {
                break;
            }
            foreach ($read as $stream) {
                $index = array_search($stream, $open, true);
                $chunk = fread($stream, 65536);
                if ($chunk === false || ($chunk === '' && feof($stream))) {
                    fclose($stream);
                    unset($open[$index]);
                    continue;
                }
                $output[$index] .= $chunk;
            }
        }
        $status = proc_close($process);
        if ($status !== 0) {
            throw new \RuntimeException('docker ' . implode(' ', $args) . " exited with $status: {$output[2]}");
        }
        return $output[1];
    }

    /**
     * Return [header fields, {directive: local value}] from `php-fpm -i` text output.
     *
     * @return array{0: array<string, string>, 1: array<string, string>}
     */
    private static function parsePhpinfo(string $text): array
    {
        $fields = [];
        $ini = [];
        $lines = Util::splitLines($text);
        $count = count($lines);
        for ($i = 0; $i < $count; $i++) {
            $parts = explode(' => ', $lines[$i]);
            if (count($parts) === 2 && !array_key_exists($parts[0], $fields)) {
                $value = $parts[1];
                // Long lists continue on the following lines, each ending with a comma but the last.
                while (Util::endsWith($value, ',')) {
                    $i++;
                    $value .= $lines[$i] ?? '';
                }
                $fields[$parts[0]] = $value;
            } elseif (count($parts) === 3 && !array_key_exists($parts[0], $ini)) {
                $ini[$parts[0]] = $parts[1];
            }
        }
        return [$fields, $ini];
    }

    /** posixpath.normpath() for relative paths. */
    private static function normpath(string $path): string
    {
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..' && $parts && end($parts) !== '..') {
                array_pop($parts);
                continue;
            }
            $parts[] = $part;
        }
        return $parts ? implode('/', $parts) : '.';
    }

    /** @param resource $stream */
    private static function readExactly($stream, int $length): string
    {
        $data = '';
        while (strlen($data) < $length && !feof($stream)) {
            $chunk = fread($stream, min(65536, $length - strlen($data)));
            if ($chunk === false) {
                break;
            }
            $data .= $chunk;
        }
        if (strlen($data) !== $length) {
            throw new \RuntimeException('truncated tar stream');
        }
        return $data;
    }

    private static function octal(string $field): int
    {
        if ($field !== '' && (ord($field[0]) & 0x80) !== 0) {
            // GNU base-256 encoding for large sizes.
            $value = ord($field[0]) & 0x7f;
            for ($i = 1, $n = strlen($field); $i < $n; $i++) {
                $value = $value * 256 + ord($field[$i]);
            }
            return $value;
        }
        $digits = trim(str_replace("\0", ' ', $field));
        return $digits === '' ? 0 : (int) octdec($digits);
    }

    /**
     * Extract the configuration-related members of a tar stream reading the stream once.
     *
     * @param resource $stream
     */
    private static function extract($stream, string $root): void
    {
        $longName = null;
        $longLink = null;
        $pax = [];
        while (true) {
            $header = self::readExactly($stream, 512);
            if (trim($header, "\0") === '') {
                break;
            }
            $size = self::octal(substr($header, 124, 12));
            $type = $header[156];
            $padded = (int) (ceil($size / 512) * 512);
            if (in_array($type, ['x', 'g', 'L', 'K'], true)) {
                $data = substr(self::readExactly($stream, $padded), 0, $size);
                if ($type === 'L') {
                    $longName = rtrim($data, "\0");
                } elseif ($type === 'K') {
                    $longLink = rtrim($data, "\0");
                } elseif ($type === 'x') {
                    $pax = self::parsePax($data);
                }
                continue;
            }
            $name = rtrim(substr($header, 0, 100), "\0");
            $linkname = rtrim(substr($header, 157, 100), "\0");
            if (substr($header, 257, 5) === 'ustar') {
                $prefix = rtrim(substr($header, 345, 155), "\0");
                if ($prefix !== '') {
                    $name = "$prefix/$name";
                }
            }
            $name = $pax['path'] ?? $longName ?? $name;
            $linkname = $pax['linkpath'] ?? $longLink ?? $linkname;
            if (isset($pax['size'])) {
                $size = (int) $pax['size'];
                $padded = (int) (ceil($size / 512) * 512);
            }
            $longName = $longLink = null;
            $pax = [];
            // Directories, links and devices carry no data even if a size is recorded.
            $hasData = in_array($type, ['0', "\0", '7'], true);
            $data = null;
            $name = self::normpath(ltrim($name, './'));
            $wanted = !Util::startsWith($name, '..') && self::wanted($name);
            if ($hasData) {
                if ($wanted && $size <= self::MAX_FILE) {
                    $data = substr(self::readExactly($stream, $padded), 0, $size);
                } else {
                    self::skip($stream, $padded);
                }
            }
            if (!$wanted) {
                continue;
            }
            $target = "$root/$name";
            if ($type === '5') {
                if (!is_dir($target)) {
                    mkdir($target, 0777, true);
                }
                continue;
            }
            if (!is_dir(dirname($target))) {
                mkdir(dirname($target), 0777, true);
            }
            if ($type === '2') {
                // Kept verbatim: the scanner itself must confine absolute targets to the root.
                symlink($linkname, $target);
            } elseif ($type === '1') {
                $source = $root . '/' . self::normpath(ltrim($linkname, './'));
                if (is_file($source)) {
                    copy($source, $target);
                }
            } elseif ($data !== null) {
                file_put_contents($target, $data);
            }
        }
    }

    private static function wanted(string $name): bool
    {
        foreach (self::EXTRACT as $prefix) {
            if (Util::startsWith($name, $prefix)) {
                return true;
            }
        }
        return false;
    }

    /** @param resource $stream */
    private static function skip($stream, int $length): void
    {
        while ($length > 0) {
            $length -= strlen(self::readExactly($stream, min(65536, $length)));
        }
    }

    /** @return array<string, string> */
    private static function parsePax(string $data): array
    {
        $records = [];
        $offset = 0;
        while ($offset < strlen($data)) {
            $space = strpos($data, ' ', $offset);
            if ($space === false) {
                break;
            }
            $length = (int) substr($data, $offset, $space - $offset);
            if ($length <= 0) {
                break;
            }
            $record = substr($data, $space + 1, $length - ($space - $offset) - 2);
            $equals = strpos($record, '=');
            if ($equals !== false) {
                $records[substr($record, 0, $equals)] = substr($record, $equals + 1);
            }
            $offset += $length;
        }
        return $records;
    }

    /** @param string|null $scannerValue */
    private static function same(string $name, ?string $scannerValue, string $displayed): bool
    {
        if ($displayed === 'no value') {
            return $scannerValue === null || $scannerValue === '';
        }
        if ($displayed === 'On' || $displayed === 'Off') {
            return Values::toBool($scannerValue) === ($displayed === 'On');
        }
        if ($name === 'error_reporting') {
            return Values::evalErrorReporting($scannerValue) === (int) $displayed;
        }
        return $scannerValue === $displayed;
    }

    /**
     * @return array{0: array{0: array<string, string>, 1: array<string, string>}, 1: array<string, Target>}
     */
    private function scanImage(string $image, string $setup, string $fpm): array
    {
        $name = 'php-ini-audit-test-' . bin2hex(random_bytes(6));
        try {
            $run = self::docker(['run', '--name', $name, $image, 'sh', '-c', "($setup) >/dev/null 2>&1 && $fpm -i"]);
            $root = Helpers::tempDir();
            $this->roots[] = $root;
            $export = proc_open(['docker', 'export', $name], [1 => ['pipe', 'w'], 2 => STDERR], $pipes);
            $this->assertIsResource($export);
            try {
                self::extract($pipes[1], $root);
                while (!feof($pipes[1])) {
                    fread($pipes[1], 65536);
                }
            } finally {
                fclose($pipes[1]);
                $status = proc_close($export);
            }
            $this->assertSame(0, $status);
        } finally {
            $cleanup = proc_open(['docker', 'rm', '-f', $name], [1 => ['file', '/dev/null', 'w'],
                2 => ['file', '/dev/null', 'w']], $unused);
            if (is_resource($cleanup)) {
                proc_close($cleanup);
            }
        }
        [$code, $out, $err] = Helpers::runCli('--root', $root, '--path-checks', 'off', '--format', 'json');
        $this->assertSame(0, $code, $err);
        $this->assertNotEmpty(json_decode($out, true, 512, JSON_THROW_ON_ERROR)['findings']);
        $fs = new FileSystem($root);
        $discovery = (new Discoverer($fs))->system();
        $discovery->resolveVersions($fs);
        $targets = [];
        foreach ((new Auditor($fs, Helpers::options(['pathChecks' => false])))->buildTargets($discovery) as $target) {
            $targets[$target->name()] = $target;
        }
        return [self::parsePhpinfo($run), $targets];
    }

    /** @return array<string, array{0: string}> */
    public function imageNames(): array
    {
        $cases = [];
        foreach (array_keys(self::images()) as $case) {
            $cases[$case] = [$case];
        }
        return $cases;
    }

    /** @dataProvider imageNames */
    public function testImages(string $case): void
    {
        [$image, $setup, $fpm, $expectedTarget] = self::images()[$case];
        [[$fields, $phpIni], $targets] = $this->scanImage($image, $setup, $fpm);
        $this->assertArrayHasKey($expectedTarget, $targets);
        $target = $targets[$expectedTarget];

        $version = array_map('intval', array_slice(explode('.', $fields['PHP Version']), 0, 3));
        $this->assertSame($version, $target->phpVersion);
        $loaded = $fields['Loaded Configuration File'];
        $this->assertSame($loaded === '(none)', $target->defaultsReason !== null);
        $scanned = [];
        foreach (explode(',', $fields['Additional .ini files parsed']) as $path) {
            $path = trim($path);
            if ($path !== '' && $path !== '(none)') {
                $scanned[] = $path;
            }
        }
        $expectedFiles = array_merge($loaded === '(none)' ? [] : [$loaded], $scanned);
        $this->assertSame($expectedFiles, $target->files);

        $config = $target->config;
        $mismatches = [];
        $skipped = array_merge(PhpParityTest::BUILD_DEPENDENT, PhpParityTest::EFFECTIVE_DEFAULTS);
        foreach ($phpIni as $directive => $displayed) {
            $directive = (string) $directive;
            $setting = $config->get($directive);
            if ($setting->unresolved()) {
                continue;
            }
            if (!$setting->isSet()) {
                if (!Directives::isKnown($directive) || in_array($directive, $skipped, true)) {
                    continue;
                }
                if (PhpParityTest::versionedDefault($directive, $version) !== null) {
                    continue;
                }
            }
            if (!self::same($directive, $setting->value, $displayed)) {
                $mismatches[$directive] = [$setting->value, $displayed];
            }
        }
        $this->assertSame([], $mismatches, 'scanner value vs php-fpm -i');
    }
}

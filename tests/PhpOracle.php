<?php

namespace PhpIniAudit\Tests;

/** Ask a real php-cgi binary what it makes of a configuration, as ground truth for the scanner. */
final class PhpOracle
{
    // CLI SAPI overrides several defaults (display_errors, html_errors, ...), php-cgi does not.
    public const ENV_VAR = 'PHP_CGI';
    private const TIMEOUT = 30;

    private const DUMP_SCRIPT = <<<'PHP'
<?php
$names = json_decode(getenv('PIA_NAMES') ?: '[]', true);
$values = [];
foreach ($names as $name) {
    $values[$name] = ini_get($name);
}
echo json_encode([
    'version' => PHP_VERSION,
    'values' => $values,
    'all' => getenv('PIA_ALL') ? ini_get_all(null, true) : null,
]);

PHP;

    private const PHPINFO_SCRIPT = <<<'PHP'
<?php
phpinfo(INFO_GENERAL | INFO_CONFIGURATION | INFO_MODULES);
echo "\n<!--pia-values-->", json_encode(ini_get_all(null, false));

PHP;

    /** @return list<string> php-cgi binaries from $PHP_CGI (PATH_SEPARATOR-separated), else the one on PATH */
    public static function cgiBinaries(): array
    {
        $configured = (string) getenv(self::ENV_VAR);
        $candidates = $configured !== '' ? explode(PATH_SEPARATOR, $configured) : [self::which('php-cgi')];
        return array_values(array_filter($candidates, static function (?string $c): bool {
            return $c !== null && $c !== '';
        }));
    }

    private static function which(string $name): ?string
    {
        foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $dir) {
            if ($dir === '') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            if (is_file($path) && is_executable($path)) {
                return $path;
            }
        }
        return null;
    }

    /** @return list<int> */
    public static function versionTuple(string $text): array
    {
        $parts = array_slice(explode('.', explode('-', $text)[0]), 0, 3);
        return array_map('intval', $parts);
    }

    /**
     * Run php-cgi with only the given configuration and return its view of the directives.
     * With $documentRoot the request is a real CGI request, so [PATH=] sections and .user.ini apply.
     *
     * @param list<string> $names
     * @return array{version: string, values: array<string, string|false|null>, all: array|null}
     */
    public static function run(string $binary, ?string $ini = null, ?string $scanDir = null, array $names = [],
                               bool $allEntries = false, ?string $scriptDir = null, ?string $documentRoot = null): array
    {
        $tmp = Helpers::tempDir();
        try {
            $directory = $scriptDir ?? $tmp;
            if (!is_dir($directory)) {
                mkdir($directory, 0777, true);
            }
            $script = $directory . '/pia_dump.php';
            file_put_contents($script, self::DUMP_SCRIPT);
            $env = [
                'PATH' => (string) getenv('PATH'),
                'PIA_NAMES' => json_encode(array_values($names)),
                'PHP_INI_SCAN_DIR' => (string) $scanDir,
            ];
            if ($allEntries) {
                $env['PIA_ALL'] = '1';
            }
            $args = $ini === null ? [$binary, '-n'] : [$binary, '-c', $ini];
            if ($documentRoot !== null) {
                $env += [
                    'REDIRECT_STATUS' => '200',
                    'GATEWAY_INTERFACE' => 'CGI/1.1',
                    'REQUEST_METHOD' => 'GET',
                    'SCRIPT_FILENAME' => $script,
                    'DOCUMENT_ROOT' => $documentRoot,
                ];
            } else {
                $args = array_merge($args, ['-q', $script]);
            }
            try {
                $stdout = self::execute($args, $env);
            } finally {
                unlink($script);
            }
        } finally {
            Helpers::removeTree($tmp);
        }
        if ($documentRoot !== null) {
            $parts = explode("\n\n", $stdout, 2);
            $stdout = end($parts);
        }
        return json_decode($stdout, true, 512, JSON_THROW_ON_ERROR);
    }

    /** @return array<string, string> */
    private static function bareEnv(): array
    {
        return ['PATH' => (string) getenv('PATH'), 'PHP_INI_SCAN_DIR' => ''];
    }

    /** Return what the PHP script $source prints under php-cgi with only the given php.ini. */
    public static function output(string $binary, string $ini, string $source): string
    {
        $script = dirname($ini) . '/pia_script.php';
        file_put_contents($script, $source);
        try {
            return self::execute([$binary, '-c', $ini, '-q', $script], self::bareEnv());
        } finally {
            unlink($script);
        }
    }

    /**
     * Return php-cgi's phpinfo() HTML and the ini_get() value of every directive, from one run.
     * The script runs from the php.ini directory, so an open_basedir naming that directory still allows it.
     *
     * @return array{0: string, 1: array<string, string|null>}
     */
    public static function phpinfo(string $binary, string $ini): array
    {
        $script = dirname($ini) . '/pia_info.php';
        file_put_contents($script, self::PHPINFO_SCRIPT);
        try {
            $stdout = self::execute([$binary, '-c', $ini, '-q', $script], self::bareEnv());
        } finally {
            unlink($script);
        }
        $parts = explode('<!--pia-values-->', $stdout);
        if (count($parts) !== 2) {
            throw new \RuntimeException('unexpected phpinfo output');
        }
        return [$parts[0], json_decode($parts[1], true, 512, JSON_THROW_ON_ERROR)];
    }

    /**
     * Run a command with exactly $env and return its stdout with "\r\n" and "\r" translated to "\n".
     *
     * @param list<string> $args
     * @param array<string, string> $env
     */
    private static function execute(array $args, array $env): string
    {
        // proc_open() drops empty variables, but an empty PHP_INI_SCAN_DIR is what disables scanning.
        $empty = [];
        foreach ($env as $name => $value) {
            if ($value === '') {
                $empty[] = "$name=";
            }
        }
        if ($empty) {
            $args = array_merge(['/usr/bin/env'], $empty, $args);
        }
        $process = proc_open($args, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
        if (!is_resource($process)) {
            throw new \RuntimeException('cannot run ' . $args[0]);
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $output = ['', ''];
        $deadline = microtime(true) + self::TIMEOUT;
        $open = [1 => $pipes[1], 2 => $pipes[2]];
        while ($open) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                proc_terminate($process, 9);
                proc_close($process);
                throw new \RuntimeException(implode(' ', $args) . ' timed out after ' . self::TIMEOUT . 's');
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
                $output[$index - 1] .= $chunk;
            }
        }
        $status = proc_close($process);
        if ($status !== 0) {
            throw new \RuntimeException(implode(' ', $args) . " exited with $status: " . $output[1]);
        }
        return str_replace(["\r\n", "\r"], "\n", $output[0]);
    }
}

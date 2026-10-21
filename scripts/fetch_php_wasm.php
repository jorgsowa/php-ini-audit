<?php
/**
 * Download the php-wasm runtime for the browser scanner into docs/assets/php-wasm/, verified against a pinned hash.
 *
 * Usage: php scripts/fetch_php_wasm.php
 */

declare(strict_types=1);

const TARBALL = 'https://registry.npmjs.org/php-wasm/-/php-wasm-0.2.0.tgz';
// npm "dist.integrity" of php-wasm@0.2.0.
const INTEGRITY = 'sha512-wID1a+RuyIlgk414FoBKM5z9UZ0sD4gl8Lu4fqy3K7d6kdZhfiC9u1/s3xJo5Is8ebj3VLiCVyp9INyZcgLuoA==';
const OUTPUT = __DIR__ . '/../docs/assets/php-wasm';
// The module graph of PhpWeb with version 8.4, plus the licence files redistribution requires.
const FILES = [
    'PhpWeb.mjs', 'PhpWebBase.mjs', 'PhpBase.mjs', 'webTransactions.mjs', 'OutputBuffer.mjs', '_Event.mjs',
    'fsOps.mjs', 'resolveDependencies.mjs', 'php8.4-web.mjs', '6733ae879e026f8b36961884052b87de4def4e15.wasm',
    'LICENSE', 'LICENSE-GPL', 'NOTICE',
];

$tarball = @file_get_contents(TARBALL);
if ($tarball === false) {
    fwrite(STDERR, 'failed to fetch ' . TARBALL . "\n");
    exit(1);
}
if (!hash_equals(INTEGRITY, 'sha512-' . base64_encode(hash('sha512', $tarball, true)))) {
    fwrite(STDERR, TARBALL . " does not match the pinned hash\n");
    exit(1);
}

$archive = tempnam(sys_get_temp_dir(), 'php-wasm');
file_put_contents($archive, $tarball);
unset($tarball);
try {
    // Stream the tar entries; the unpacked package is too large to hold in memory.
    $tar = gzopen($archive, 'rb');
    if (!is_dir(OUTPUT)) {
        mkdir(OUTPUT, 0777, true);
    }
    $wanted = array_fill_keys(FILES, true);
    while ($wanted && strlen($header = (string) gzread($tar, 512)) === 512 && trim($header, "\0") !== '') {
        $name = rtrim(substr($header, 0, 100), "\0");
        $size = octdec(rtrim(substr($header, 124, 12), "\0 "));
        $padding = (512 - $size % 512) % 512;
        $file = substr($name, strlen('package/'));
        if (strncmp($name, 'package/', 8) !== 0 || !isset($wanted[$file])) {
            gzseek($tar, $size + $padding, SEEK_CUR);
            continue;
        }
        $out = fopen(OUTPUT . "/$file", 'wb');
        for ($left = $size; $left > 0; $left -= strlen($chunk)) {
            $chunk = (string) gzread($tar, min(1 << 20, $left));
            if ($chunk === '') {
                throw new RuntimeException("truncated archive at $file");
            }
            fwrite($out, $chunk);
        }
        fclose($out);
        gzseek($tar, $padding, SEEK_CUR);
        unset($wanted[$file]);
    }
    gzclose($tar);
    if ($wanted) {
        throw new RuntimeException('missing from the archive: ' . implode(', ', array_keys($wanted)));
    }
} finally {
    unlink($archive);
}
printf("wrote %d files to docs/assets/php-wasm/\n", count(FILES));
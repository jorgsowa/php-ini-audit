<?php
/** Shared by the build scripts: autoload src/ and concatenate it into one self-contained PHP file. */

const SRC = __DIR__ . '/../src';

spl_autoload_register(static function (string $class): void {
    $prefix = 'PhpIniAudit\\';
    if (strncmp($class, $prefix, strlen($prefix)) === 0) {
        $file = SRC . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});

/** @return list<string> paths relative to src/, sorted */
function source_files(): array
{
    $files = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(SRC, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        if ($file->getExtension() === 'php') {
            $files[] = substr($file->getPathname(), strlen(SRC) + 1);
        }
    }
    sort($files, SORT_STRING);
    return $files;
}

/** Every class in one file; each file keeps its own namespace statement, which also resets its imports. */
function bundle_source(): string
{
    $parts = ["<?php\n"];
    foreach (source_files() as $file) {
        $code = file_get_contents(SRC . "/$file");
        $parts[] = "\n// src/$file\n" . preg_replace('/^<\?php\s*/', '', $code);
    }
    return implode('', $parts);
}

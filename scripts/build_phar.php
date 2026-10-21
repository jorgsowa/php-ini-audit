<?php
/**
 * Build a single-file executable: build/php-ini-audit.phar.
 *
 * Usage: php -d phar.readonly=0 scripts/build_phar.php
 */

require __DIR__ . '/bundle.php';

$output = __DIR__ . '/../build/php-ini-audit.phar';
if (ini_get('phar.readonly')) {
    fwrite(STDERR, "phar.readonly is on; run: php -d phar.readonly=0 scripts/build_phar.php\n");
    exit(2);
}
if (!is_dir(dirname($output))) {
    mkdir(dirname($output), 0777, true);
}
@unlink($output);

$phar = new Phar($output, 0, 'php-ini-audit.phar');
$phar->startBuffering();
foreach (source_files() as $file) {
    $phar->addFile(SRC . "/$file", "src/$file");
}
// Only the main script may start with a shebang; inside the archive it would be printed.
$entry = preg_replace('/^#!.*\n/', '', file_get_contents(__DIR__ . '/../bin/php-ini-audit'));
$phar->addFromString('bin/php-ini-audit', $entry);
$phar->setStub("#!/usr/bin/env php\n<?php\nPhar::mapPhar('php-ini-audit.phar');\n"
    . "require 'phar://php-ini-audit.phar/bin/php-ini-audit';\n__HALT_COMPILER();\n");
$phar->stopBuffering();
chmod($output, 0755);
echo "wrote build/php-ini-audit.phar\n";

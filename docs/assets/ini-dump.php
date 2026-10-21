<?php
header('Content-Type: text/plain');
header('Cache-Control: no-store');
// Credentials only need to be known as set.
$show = fn ($name, $value) => (string) $value === '' ? 'no value'
    : (preg_match('/(^|[._])(pw|pass|passwd|password|secret)$/i', $name) ? '(set)' : $value);
echo 'PHP Version => ', PHP_VERSION, "\nServer API => ", PHP_SAPI, "\nSystem => ", PHP_OS_FAMILY,
    "\nLoaded Configuration File => ", php_ini_loaded_file() ?: '(none)',
    "\nAdditional .ini files parsed => ", str_replace(",\n", ', ', trim((string) php_ini_scanned_files())) ?: '(none)', "\n\n";
foreach (ini_get_all(null, true) as $name => $value) {
    echo $name, ' => ', $show($name, $value['local_value']), ' => ', $show($name, $value['global_value']), "\n";
}
foreach (get_loaded_extensions() as $extension) {
    echo "\n", $extension, "\n";
}

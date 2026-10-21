<?php

// Composer-free, so the tests also run with a downloaded phpunit.phar.
spl_autoload_register(static function (string $class): void {
    foreach (['PhpIniAudit\\Tests\\' => __DIR__ . '/', 'PhpIniAudit\\' => __DIR__ . '/../src/'] as $prefix => $dir) {
        if (strncmp($class, $prefix, strlen($prefix)) === 0) {
            $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require $file;
            }
            return;
        }
    }
});

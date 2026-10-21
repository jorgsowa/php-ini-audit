<?php

namespace PhpIniAudit\Rules\Htaccess;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\FileContext;
use PhpIniAudit\Rules\FileRule;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Support\PhpExtensions;
use PhpIniAudit\Severity;

final class NonPhpHandler extends FileRule
{
    public const ID = 'HTA-001';
    public const TITLE = 'Non-PHP files mapped to the PHP handler';
    public const SEVERITY = Severity::HIGH;
    public const CWE = 'CWE-434';
    public const DESCRIPTION = 'AddType/AddHandler/SetHandler mapping images, text or every file to PHP makes uploads '
        . 'executable.';
    public const RECOMMENDATION = 'Map only .php to the PHP handler, inside <FilesMatch "\\.php$">.';

    private const NON_PHP_PATTERN =
        '/jpe?g|png|gif|bmp|webp|svg|ico|txt|html?|css|js|json|xml|pdf|zip|docx?|xlsx?|csv|mp[34]|\.\*|^\.$|^\*$/i';

    public function check(FileContext $fctx): iterable
    {
        $handlers = property_exists($fctx->file, 'handlers') ? $fctx->file->handlers : [];
        foreach ($handlers as $mapping) {
            if ($mapping->extensions) {
                $extra = array_values(array_filter($mapping->extensions, static function (string $e): bool {
                    return !PhpExtensions::isPhp('.' . ltrim($e, '.'));
                }));
                if ($extra) {
                    yield new Hit("{$mapping->statement} maps " . self::names($extra) . ' to PHP', [], null,
                        Confidence::HIGH, $mapping->location);
                }
            } elseif ($mapping->filesPattern === null) {
                yield new Hit("{$mapping->statement} executes every file in the directory as PHP", [], null,
                    Confidence::HIGH, $mapping->location);
            } elseif (preg_match(self::NON_PHP_PATTERN, $mapping->filesPattern)) {
                yield new Hit(
                    "{$mapping->statement} inside <Files {$mapping->filesPattern}> covers non-PHP files",
                    [],
                    null,
                    Confidence::MEDIUM,
                    $mapping->location
                );
            }
        }
    }
}

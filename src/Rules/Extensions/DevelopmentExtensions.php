<?php

namespace PhpIniAudit\Rules\Extensions;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class DevelopmentExtensions extends ConfigRule
{
    public const ID = 'EXT-003';
    public const TITLE = 'Development or profiling extension loaded';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['extension', 'zend_extension'];
    public const PRODUCTION_ONLY = true;
    public const CWE = 'CWE-489';
    public const DESCRIPTION = 'Profilers, coverage drivers and runtime-patching extensions (uopz, runkit) are not '
        . 'meant for production and can change behaviour or leak data.';
    public const RECOMMENDATION = 'Remove development extensions from production images.';

    private const DEV_EXTENSIONS = ['xhprof', 'tideways', 'tideways_xhprof', 'pcov', 'uopz', 'runkit', 'runkit7',
        'spx'];

    public function check(Context $ctx): iterable
    {
        foreach (self::DEV_EXTENSIONS as $name) {
            $directive = $ctx->loadedExtension($name);
            if ($directive !== null) {
                yield new Hit("$name is loaded", [$directive]);
            }
        }
    }
}

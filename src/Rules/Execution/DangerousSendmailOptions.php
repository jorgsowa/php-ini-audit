<?php

namespace PhpIniAudit\Rules\Execution;

use PhpIniAudit\Paths;
use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;
use PhpIniAudit\Values;

final class DangerousSendmailOptions extends ConfigRule
{
    public const ID = 'EXEC-013';
    public const TITLE = 'Dangerous sendmail options configured';
    public const SEVERITY = Severity::HIGH;
    public const DIRECTIVES = ['sendmail_path', 'mail.force_extra_parameters'];
    public const CWE = 'CWE-88';
    public const DESCRIPTION = "sendmail options such as -X (log file), -O/-C (alternate queue/config) or Exim's -be "
        . '(expansion test) let mail() write attacker-influenced files or evaluate expressions.';
    public const RECOMMENDATION = 'Keep sendmail_path to an absolute binary with -t -i, and do not force extra '
        . 'parameters.';

    private const DANGEROUS_OPTION = '/(?:^|\s)(-X|-O|-C|-be)\S*/';

    public function check(Context $ctx): iterable
    {
        foreach (['sendmail_path', 'mail.force_extra_parameters'] as $name) {
            $setting = $ctx->get($name);
            preg_match_all(self::DANGEROUS_OPTION, $setting->text(), $matches);
            $flags = array_values(array_unique($matches[1]));
            sort($flags, SORT_STRING);
            if ($flags) {
                yield new Hit("{$setting->describe()} contains " . self::names($flags), [$setting]);
            }
        }
        $path = $ctx->get('sendmail_path');
        $binary = $path->text() !== '' ? (Values::splitWhitespace($path->text())[0] ?? '') : '';
        if ($binary !== '' && !Paths::isAbsolute($binary)) {
            yield new Hit('sendmail_path binary ' . Util::repr($binary) . ' is resolved through $PATH', [$path],
                Severity::LOW);
        }
    }
}

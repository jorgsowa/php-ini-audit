<?php

namespace PhpIniAudit\Rules\Disclosure;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;

final class MailScriptHeader extends ConfigRule
{
    public const ID = 'ERR-007';
    public const TITLE = 'Script path added to outgoing mail headers';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['mail.add_x_header'];
    public const CWE = 'CWE-200';
    public const DESCRIPTION = "mail.add_x_header adds X-PHP-Originating-Script with the script's UID and file name "
        . 'to every message.';
    public const RECOMMENDATION = 'Set mail.add_x_header = Off.';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('mail.add_x_header');
        if ($setting->asBool()) {
            yield new Hit('mail.add_x_header is On', [$setting]);
        }
    }
}

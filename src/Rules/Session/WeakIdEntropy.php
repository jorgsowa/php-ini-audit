<?php

namespace PhpIniAudit\Rules\Session;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class WeakIdEntropy extends ConfigRule
{
    public const ID = 'SESS-008';
    public const TITLE = 'Weak session ID entropy';
    public const SEVERITY = Severity::HIGH;
    public const DIRECTIVES = ['session.sid_length', 'session.sid_bits_per_character'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-331';
    public const DESCRIPTION = 'Session IDs need at least 128 bits of entropy (sid_length x sid_bits_per_character) '
        . 'to resist brute force.';
    public const RECOMMENDATION = 'Keep sid_length >= 32 with sid_bits_per_character = 4, or use 5/6 bits per '
        . 'character.';

    public function check(Context $ctx): iterable
    {
        $length = $ctx->get('session.sid_length');
        $bits = $ctx->get('session.sid_bits_per_character');
        if (!in_array($bits->asInt(), [4, 5, 6], true)) {
            return;
        }
        $entropy = max($length->asInt(), 22) * $bits->asInt();
        if ($entropy < 64) {
            yield new Hit("session IDs carry ~$entropy bits of entropy", [$length, $bits]);
        } elseif ($entropy < 128) {
            yield new Hit("session IDs carry ~$entropy bits of entropy", [$length, $bits], Severity::LOW);
        }
    }
}

<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Directive;
use PhpIniAudit\Setting;

/** Why a configuration is exposed to an advisory. */
final class Exposure
{
    public string $reason;
    /** @var list<Setting|Directive> */
    public array $evidence;
    public int $confidence;

    /** @param list<Setting|Directive> $evidence */
    public function __construct(string $reason, array $evidence = [], int $confidence = Confidence::HIGH)
    {
        $this->reason = $reason;
        $this->evidence = array_values($evidence);
        $this->confidence = $confidence;
    }
}

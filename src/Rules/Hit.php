<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Directive;
use PhpIniAudit\Location;
use PhpIniAudit\Setting;

final class Hit
{
    public string $message;
    /** @var list<Setting|Directive> */
    public array $evidence;
    public ?int $severity;
    public int $confidence;
    public ?Location $location;

    /** @param list<Setting|Directive> $evidence */
    public function __construct(string $message, array $evidence = [], ?int $severity = null,
        int $confidence = Confidence::HIGH, ?Location $location = null)
    {
        $this->message = $message;
        $this->evidence = array_values($evidence);
        $this->severity = $severity;
        $this->confidence = $confidence;
        $this->location = $location;
    }
}

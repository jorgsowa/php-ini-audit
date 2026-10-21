<?php

namespace PhpIniAudit;

final class Options
{
    public string $profile = 'production';
    public ?string $sapi = null;
    /** @var list<int>|null */
    public ?array $phpVersion = null;
    public bool $pathChecks = true;
    /** @var list<string> */
    public array $webroots = [];
    public int $minSeverity = Severity::INFO;
    /** @var list<string> */
    public array $only = [];
    /** @var list<string> */
    public array $skip = [];
}

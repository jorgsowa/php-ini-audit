<?php

namespace PhpIniAudit;

final class Installation
{
    public string $label;
    public ?string $ini;
    /** @var list<string> */
    public array $scanFiles = [];
    /** @var list<string> */
    public array $scanDirs = [];
    /** @var list<string> */
    public array $fpmFiles = [];
    public string $sapi = 'unknown';
    /** @var list<int>|null */
    public ?array $phpVersion = null;
    public ?string $versionSource = null;
    public bool $versionBackports = false;
    public ?string $defaultsReason = null;

    public function __construct(string $label, ?string $ini)
    {
        $this->label = $label;
        $this->ini = $ini;
    }
}

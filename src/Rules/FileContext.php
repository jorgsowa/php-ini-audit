<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\FpmFile;
use PhpIniAudit\HtaccessFile;
use PhpIniAudit\IniFile;
use PhpIniAudit\PathInspector;

/** What a file-scope rule sees: one parsed file, independent of how it is layered. */
final class FileContext
{
    /** @var IniFile|FpmFile|HtaccessFile */
    public $file;
    public string $profile;
    /** @var list<int>|null */
    public ?array $phpVersion;
    public ?PathInspector $paths;

    public function __construct($file, string $profile, ?array $phpVersion, ?PathInspector $paths = null)
    {
        $this->file = $file;
        $this->profile = $profile;
        $this->phpVersion = $phpVersion;
        $this->paths = $paths;
    }

    public function path(): string
    {
        return $this->file->path;
    }

    public function kind(): string
    {
        return $this->file->kind;
    }
}

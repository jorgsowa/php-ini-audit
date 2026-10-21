<?php

namespace PhpIniAudit;

final class Target
{
    public string $label;
    public string $sapi;
    /** @var list<int>|null */
    public ?array $phpVersion;
    /** @var list<string> */
    public array $files;
    public EffectiveConfig $config;
    public ?string $versionSource = null;
    public bool $versionBackports = false;
    public string $platform = 'posix';
    /** @var list<Directive> */
    public array $layers = [];
    public ?string $overlay = null;
    public ?FpmPool $pool = null;
    /** @var list<FpmPool> */
    public array $pools = [];
    public ?string $defaultsReason = null;
    public bool $synthetic = false;
    /** @var array<string, true>|null Directive names a phpinfo() dump lists; the rest do not exist in that PHP build. */
    public ?array $observed = null;

    public function __construct(string $label, string $sapi, ?array $phpVersion, array $files, EffectiveConfig $config)
    {
        $this->label = $label;
        $this->sapi = $sapi;
        $this->phpVersion = $phpVersion;
        $this->files = $files;
        $this->config = $config;
    }

    public function name(): string
    {
        return $this->overlay !== null && $this->overlay !== '' ? "{$this->label} + {$this->overlay}" : $this->label;
    }

    public function toArray(): array
    {
        return [
            'name' => $this->name(),
            'base' => $this->label,
            'overlay' => $this->overlay,
            'sapi' => $this->sapi,
            'php_version' => $this->phpVersion ? implode('.', $this->phpVersion) : null,
            'php_version_source' => $this->versionSource,
            'files' => $this->files,
            'defaults_only' => $this->defaultsReason !== null,
        ];
    }
}

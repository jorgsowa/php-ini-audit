<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\EffectiveConfig;
use PhpIniAudit\FpmPool;
use PhpIniAudit\PathInspector;
use PhpIniAudit\Setting;
use PhpIniAudit\Util;

/** What a config-scope or pool-scope rule sees. */
final class Context
{
    public EffectiveConfig $config;
    public string $sapi;
    public string $profile;
    /** @var list<int>|null */
    public ?array $phpVersion;
    public ?string $versionSource = null;
    public bool $versionBackports = false;
    public string $platform = 'posix';
    public ?PathInspector $paths = null;
    public ?FpmPool $pool = null;
    /** @var list<FpmPool> */
    public array $pools = [];
    public ?string $defaultsReason = null;
    public ?string $overlayKind = null;
    public array $extra = [];

    public function __construct(EffectiveConfig $config, string $sapi, string $profile, ?array $phpVersion)
    {
        $this->config = $config;
        $this->sapi = $sapi;
        $this->profile = $profile;
        $this->phpVersion = $phpVersion;
    }

    public function get(string $name): Setting
    {
        return $this->config->get($name);
    }

    public function on(string $name): bool
    {
        return $this->get($name)->asBool();
    }

    public function production(): bool
    {
        return $this->profile === 'production';
    }

    public function isWeb(): bool
    {
        return in_array($this->sapi, Base::WEB_SAPIS, true);
    }

    public function versionBelow(int $major, int $minor = 0): ?bool
    {
        if ($this->phpVersion === null) {
            return null;
        }
        return Util::compare($this->phpVersion, [$major, $minor]) < 0;
    }
}

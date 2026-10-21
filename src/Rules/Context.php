<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Directive;
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
        return in_array($this->sapi, Sapis::WEB, true);
    }

    public function usesFpm(): bool
    {
        return $this->sapi === 'fpm' || (bool) $this->pools;
    }

    /** @return array<string, true> lower-cased names in disable_functions */
    public function disabledFunctions(): array
    {
        $disabled = [];
        foreach ($this->get('disable_functions')->asList() as $name) {
            $disabled[strtolower($name)] = true;
        }
        return $disabled;
    }

    /** The extension or zend_extension directive that loads $name, matched by file name. */
    public function loadedExtension(string $name): ?Directive
    {
        foreach ($this->config->extensions as $directive) {
            $path = str_replace('\\', '/', $directive->value);
            $slash = strrpos($path, '/');
            $base = strtolower($slash === false ? $path : substr($path, $slash + 1));
            $stem = preg_replace('/^(php_)?|(\.so|\.dll)$/', '', $base);
            if ($stem === $name) {
                return $directive;
            }
        }
        return null;
    }

    public function versionBelow(int $major, int $minor = 0): ?bool
    {
        if ($this->phpVersion === null) {
            return null;
        }
        return Util::compare($this->phpVersion, [$major, $minor]) < 0;
    }
}

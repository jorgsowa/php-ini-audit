<?php

namespace PhpIniAudit;

/** Effective configuration: the result of applying layered files in PHP's own order. */
final class EffectiveConfig
{
    private const PER_DIR_ONLY = [OverlayKind::USER_INI, OverlayKind::HTACCESS];
    private const LIST_DIRECTIVES = ['extension', 'zend_extension'];

    /** @var array<string, Directive> */
    private array $current = [];
    /** @var array<string, list<Directive>> */
    public array $history = [];
    /** @var list<Directive> */
    public array $extensions = [];
    /** @var list<Directive> */
    public array $ineffective = [];
    public ?string $overlayKind;
    /** @var list<Directive> */
    private array $overlay = [];

    /**
     * @param iterable<Directive> $layers
     * @param iterable<Directive> $overlay
     */
    public function __construct(iterable $layers, iterable $overlay = [], ?string $overlayKind = null)
    {
        $this->overlayKind = $overlayKind;
        foreach ($layers as $directive) {
            $this->apply($directive, null);
        }
        foreach ($overlay as $directive) {
            $applied = $this->apply($directive, $overlayKind);
            if ($applied !== null && !in_array($applied, $this->overlay, true)) {
                $this->overlay[] = $applied;
            }
        }
    }

    private function apply(Directive $directive, ?string $kind): ?Directive
    {
        if (in_array($kind, self::PER_DIR_ONLY, true) && !Directives::settablePerDir($directive->name)) {
            $this->ineffective[] = $directive;
            return null;
        }
        if (in_array($directive->name, self::LIST_DIRECTIVES, true)) {
            $this->extensions[] = $directive;
            return $directive;
        }
        $previous = $this->current[$directive->name] ?? null;
        if ($kind === OverlayKind::FPM_POOL && $directive->admin && in_array($directive->name, Directives::FPM_APPENDING, true)
            && $previous !== null && $previous->value !== '') {
            $directive = $directive->withValue("{$previous->value},{$directive->value}");
        }
        $this->history[$directive->name][] = $directive;
        $this->current[$directive->name] = $directive;
        return $directive;
    }

    public function get(string $name): Setting
    {
        $directive = $this->current[$name] ?? null;
        if ($directive === null) {
            return new Setting($name, Directives::default($name));
        }
        return new Setting($name, $directive->value, $directive, array_slice($this->history[$name], 0, -1));
    }

    /** @return list<Setting> */
    public function explicit(): array
    {
        $names = array_map('strval', array_keys($this->current));
        sort($names, SORT_STRING);
        return array_map([$this, 'get'], $names);
    }

    public function isOverlay(?Directive $directive): bool
    {
        return $directive !== null && in_array($directive, $this->overlay, true);
    }

    public function isIneffective(?Directive $directive): bool
    {
        return $directive !== null && in_array($directive, $this->ineffective, true);
    }

    /** @return list<Directive> */
    public function overlayDirectives(): array
    {
        return Util::sortBy($this->overlay, static function (Directive $d): array {
            return [$d->location->path, $d->location->line ?? 0];
        });
    }
}

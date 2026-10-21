<?php

namespace PhpIniAudit\Rules;

final class Registry
{
    /** Registration order matches the order the rule modules are loaded. */
    private const MODULES = [Disclosure::class, Execution::class, Extensions::class, FilesAndPaths::class, Hygiene::class,
        Resources::class, Server::class, Session::class, Vulnerabilities::class];

    private const ATTRIBUTES = ['severity', 'description', 'recommendation', 'directives', 'scope', 'sapis',
        'production_only', 'dev_severity', 'cwe', 'references'];

    /** @var array<string, Rule>|null */
    private static ?array $rules = null;

    /**
     * Register a rule; $attributes uses the snake_case keys of ATTRIBUTES.
     * The check receives a Context (or FileContext for scope "file") and returns iterable<Hit>, usually by yielding.
     */
    public static function rule(string $id, string $title, array $attributes, callable $check): void
    {
        if (isset(self::$rules[$id])) {
            throw new \LogicException("duplicate rule id $id");
        }
        $unknown = array_diff(array_keys($attributes), self::ATTRIBUTES);
        if ($unknown) {
            throw new \LogicException("$id: unknown rule attributes " . implode(', ', $unknown));
        }
        $rule = new Rule($id, $title, $attributes['severity'], $attributes['description'],
            $attributes['recommendation'], $check);
        $rule->directives = array_values($attributes['directives'] ?? []);
        $rule->scope = $attributes['scope'] ?? 'config';
        $rule->sapis = isset($attributes['sapis']) ? array_values($attributes['sapis']) : null;
        $rule->productionOnly = $attributes['production_only'] ?? false;
        $rule->devSeverity = $attributes['dev_severity'] ?? null;
        $rule->cwe = $attributes['cwe'] ?? null;
        $rule->references = array_values($attributes['references'] ?? []);
        self::$rules[$id] = $rule;
    }

    /** @return array<string, Rule> rule id => rule, in registration order */
    public static function all(): array
    {
        if (self::$rules === null) {
            self::$rules = [];
            foreach (self::MODULES as $module) {
                $module::register();
            }
        }
        return self::$rules;
    }

    public static function get(string $id): ?Rule
    {
        return self::all()[$id] ?? null;
    }

    /** @return list<string> */
    public static function securityDirectives(): array
    {
        $names = [];
        foreach (self::all() as $rule) {
            foreach ($rule->directives as $name) {
                $names[$name] = true;
            }
        }
        return array_map('strval', array_keys($names));
    }
}

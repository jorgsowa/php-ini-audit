<?php

namespace PhpIniAudit;

/** What phpinfo() shows: general fields, directive table and loaded modules. */
final class PhpinfoDump
{
    /** @var array<string, string> */
    public array $fields = [];
    /** @var array<string, array{0: string, 1: int}> directive => [value, line] */
    public array $settings = [];
    /** @var list<array{0: string, 1: int}> [module, line] */
    public array $modules = [];
}

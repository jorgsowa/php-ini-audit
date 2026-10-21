<?php

namespace PhpIniAudit\Rules;

/** Evaluated once per PHP-FPM pool; Context::$pool is always set. */
abstract class PoolRule extends ConfigRule
{
    public const SCOPE = 'pool';
}

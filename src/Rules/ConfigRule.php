<?php

namespace PhpIniAudit\Rules;

/** Evaluated once per effective configuration (php.ini plus scan-dir files, pool or per-directory overlay). */
abstract class ConfigRule extends Rule
{
    /** @return iterable<Hit> */
    abstract public function check(Context $ctx): iterable;
}

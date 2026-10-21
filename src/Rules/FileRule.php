<?php

namespace PhpIniAudit\Rules;

/** Evaluated once per parsed file, independent of how the file is layered. */
abstract class FileRule extends Rule
{
    public const SCOPE = 'file';

    /** @return iterable<Hit> */
    abstract public function check(FileContext $ctx): iterable;
}

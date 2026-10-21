<?php

namespace PhpIniAudit;

final class ParseIssue
{
    public Location $location;
    public string $message;

    public function __construct(Location $location, string $message)
    {
        $this->location = $location;
        $this->message = $message;
    }
}

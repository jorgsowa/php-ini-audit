<?php

namespace PhpIniAudit;

final class Discovery
{
    /** @var list<Installation> */
    public array $installations = [];
    /** @var list<string> */
    public array $userInis = [];
    /** @var list<string> */
    public array $htaccess = [];
    /** @var list<string> */
    public array $warnings = [];

    /** Upgrade path-derived MAJOR.MINOR to an exact version where the system records one. */
    public function resolveVersions(FileSystem $fs): void
    {
        $evidence = (new VersionFinder($fs))->collect();
        foreach ($this->installations as $installation) {
            $branch = $installation->phpVersion ? array_slice($installation->phpVersion, 0, 2) : null;
            $near = $installation->ini;
            if ($near === null || $near === '') {
                $near = $installation->scanDirs[0] ?? null;
            }
            $chosen = Versions::pick($evidence, $branch, $near);
            if ($chosen !== null) {
                $installation->phpVersion = $chosen->version;
                $installation->versionSource = $chosen->source;
                $installation->versionBackports = $chosen->backports;
            }
        }
    }
}

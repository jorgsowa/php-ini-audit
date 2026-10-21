<?php

namespace PhpIniAudit;

/** Metadata-only inspection of paths referenced by configuration values. */
final class PathInspector
{
    public FileSystem $fs;
    /** @var list<string> */
    public array $webroots;
    public bool $posixModes;

    /** @param list<string> $webroots */
    public function __construct(FileSystem $fs, array $webroots = [])
    {
        $this->fs = $fs;
        $this->webroots = array_map([Paths::class, 'normpath'], array_values($webroots));
        $this->posixModes = !Paths::isWindows();
    }

    public function facts(string $path): ?PathFacts
    {
        if (!Util::startsWith($path, '/') || !$this->posixModes) {
            return null;
        }
        $normalized = Paths::normpath($path);
        $info = $this->fs->stat($normalized);
        if ($info === null) {
            $ancestor = $this->nearestExistingParent($normalized);
            $facts = new PathFacts($normalized, false);
            $facts->writableAncestor = $ancestor !== null && $ancestor[1] ? $ancestor[0] : null;
            $facts->writableAncestorSticky = $ancestor !== null && $ancestor[2];
            return $facts;
        }
        $mode = $info['mode'];
        $isDir = Stat::isDir($mode);
        $parent = null;
        $parentSticky = false;
        if (!$isDir) {
            $parentInfo = $this->fs->stat(Paths::dirname($normalized));
            if ($parentInfo !== null && ($parentInfo['mode'] & Stat::S_IWOTH)) {
                $parent = Paths::dirname($normalized);
                $parentSticky = ($parentInfo['mode'] & Stat::S_ISVTX) !== 0;
            }
        }
        $facts = new PathFacts($normalized, true);
        $facts->isDir = $isDir;
        $facts->worldWritable = ($mode & Stat::S_IWOTH) !== 0;
        $facts->worldReadable = ($mode & Stat::S_IROTH) !== 0;
        $facts->groupWritable = ($mode & Stat::S_IWGRP) !== 0;
        $facts->sticky = ($mode & Stat::S_ISVTX) !== 0;
        $facts->writableAncestor = $parent;
        $facts->writableAncestorSticky = $parentSticky;
        return $facts;
    }

    /** @return array{string, bool, bool}|null */
    private function nearestExistingParent(string $path): ?array
    {
        $current = Paths::dirname($path);
        while (true) {
            $info = $this->fs->stat($current);
            if ($info !== null) {
                if (!Stat::isDir($info['mode'])) {
                    return null;
                }
                return [$current, ($info['mode'] & Stat::S_IWOTH) !== 0, ($info['mode'] & Stat::S_ISVTX) !== 0];
            }
            if ($current === '/') {
                return null;
            }
            $current = Paths::dirname($current);
        }
    }

    /** @return int|null a Confidence */
    public function webrootMatch(string $path): ?int
    {
        if (!Paths::isAbsolute($path)) {
            return null;
        }
        $normalized = Paths::normpath(str_replace('\\', '/', $path));
        foreach ($this->webroots as $root) {
            if ($normalized === $root || Util::startsWith($normalized, rtrim($root, '/') . '/')) {
                return Confidence::HIGH;
            }
        }
        if ($this->webroots) {
            return null;
        }
        return preg_match(Paths::WEBROOT_HINT, $normalized) ? Confidence::LOW : null;
    }
}

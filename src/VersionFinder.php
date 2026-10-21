<?php

namespace PhpIniAudit;

/** Find exact PHP versions from files on disk (headers, package databases) without running PHP. */
final class VersionFinder
{
    public FileSystem $fs;

    public function __construct(FileSystem $fs)
    {
        $this->fs = $fs;
    }

    private function read(string $path): ?string
    {
        try {
            return $this->fs->readText($path);
        } catch (ReadError $exception) {
            return null;
        }
    }

    /** @return list<VersionEvidence> */
    public function collect(): array
    {
        $found = [];
        foreach (Versions::HEADER_PATTERNS as $pattern) {
            foreach ($this->fs->glob($pattern) as $path) {
                $text = $this->read($path);
                if (preg_match(Versions::HEADER_VERSION, $text ?? '', $match)) {
                    $found[] = new VersionEvidence(self::ints($match), $path);
                }
            }
        }
        array_push($found, ...$this->dpkg());
        array_push($found, ...$this->apk());
        foreach (Versions::HOMEBREW_LINKS as $pattern) {
            foreach ($this->fs->glob($pattern) as $link) {
                if (preg_match(Versions::UPSTREAM, Paths::basename($this->fs->resolve($link)), $match)) {
                    $found[] = new VersionEvidence(self::ints($match), $link);
                }
            }
        }
        return self::dedupe($found);
    }

    /** @return list<int> */
    private static function ints(array $match): array
    {
        return [(int) $match[1], (int) $match[2], (int) $match[3]];
    }

    /**
     * @param list<VersionEvidence> $found
     * @return list<VersionEvidence>
     */
    private static function dedupe(array $found): array
    {
        $unique = [];
        foreach ($found as $evidence) {
            $key = implode('.', $evidence->version) . "\0" . $evidence->source;
            if (!array_key_exists($key, $unique)) {
                $unique[$key] = $evidence;
            }
        }
        return array_values($unique);
    }

    /** @return \Generator<int, array<string, string>> */
    private function stanzas(string $path): \Generator
    {
        $text = $this->read($path);
        if ($text === null || $text === '') {
            return;
        }
        foreach (explode("\n\n", $text) as $block) {
            $fields = [];
            foreach (Util::splitLines($block) as $line) {
                $colon = strpos($line, ':');
                if ($colon !== false && !Util::startsWith($line, ' ')) {
                    $fields[trim(substr($line, 0, $colon))] = trim(substr($line, $colon + 1));
                }
            }
            yield $fields;
        }
    }

    /** @return list<VersionEvidence> */
    private function dpkg(): array
    {
        $found = [];
        foreach ($this->stanzas(Versions::DPKG_STATUS) as $fields) {
            $package = (string) ($fields['Package'] ?? '');
            $status = trim((string) ($fields['Status'] ?? ''));
            $words = $status === '' ? [] : preg_split('/\s+/', $status);
            if (!preg_match(Versions::DPKG_PACKAGE, $package) || !in_array('installed', $words, true)) {
                continue;
            }
            $version = (string) ($fields['Version'] ?? '');
            if (preg_match(Versions::UPSTREAM, $version, $match)) {
                // deb.sury.org builds track upstream releases; distribution builds backport fixes.
                $found[] = new VersionEvidence(self::ints($match), Versions::DPKG_STATUS . " ($package $version)",
                    !Util::contains($version, 'sury'));
            }
        }
        return $found;
    }

    /** @return list<VersionEvidence> */
    private function apk(): array
    {
        $found = [];
        foreach ($this->stanzas(Versions::APK_INSTALLED) as $fields) {
            $package = (string) ($fields['P'] ?? '');
            if (!preg_match(Versions::APK_PACKAGE, $package)) {
                continue;
            }
            $version = (string) ($fields['V'] ?? '');
            if (preg_match(Versions::UPSTREAM, $version, $match)) {
                $found[] = new VersionEvidence(self::ints($match), Versions::APK_INSTALLED . " ($package $version)");
            }
        }
        return $found;
    }
}

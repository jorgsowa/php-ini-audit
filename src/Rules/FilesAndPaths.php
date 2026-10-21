<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Paths;
use PhpIniAudit\Setting;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

/** Filesystem confinement and the safety of paths referenced by the configuration. */
final class FilesAndPaths
{
    private const WINDOWS_LIST = '/(^|;)[A-Za-z]:[\\\\\/]/';

    /** [directive, kind, purpose, severity when writable, severity when web-served] */
    public const PATH_SPECS = [
        ['extension_dir', 'dir', 'PHP loads extension shared objects from it', Severity::CRITICAL, Severity::HIGH],
        ['auto_prepend_file', 'file', 'it is executed before every script', Severity::CRITICAL, null],
        ['auto_append_file', 'file', 'it is executed after every script', Severity::CRITICAL, null],
        ['include_path', 'list', 'include/require search it', Severity::HIGH, null],
        ['open_basedir', 'list', 'scripts may read and write there', Severity::LOW, null],
        ['session.save_path', 'session', 'it stores session data', Severity::MEDIUM, Severity::HIGH],
        ['upload_tmp_dir', 'dir', 'it receives uploaded files', Severity::LOW, Severity::HIGH],
        ['sys_temp_dir', 'dir', 'it holds temporary files', null, Severity::MEDIUM],
        ['error_log', 'log', 'it receives error messages', Severity::MEDIUM, Severity::HIGH],
        ['mail.log', 'log', 'it records every mail() call', Severity::MEDIUM, Severity::HIGH],
        ['opcache.file_cache', 'dir', 'PHP executes the compiled opcodes cached there', Severity::HIGH, Severity::HIGH],
        ['opcache.preload', 'file', 'it is executed at server start-up', Severity::CRITICAL, null],
        ['opcache.lockfile_path', 'dir', 'it holds OPcache lock files', Severity::LOW, null],
        ['opcache.error_log', 'log', 'it receives OPcache errors', Severity::MEDIUM, Severity::HIGH],
        ['opcache.blacklist_filename', 'file', 'it controls which files bypass OPcache', Severity::LOW, null],
        ['browscap', 'file', 'get_browser() parses it', Severity::LOW, null],
        ['openssl.cafile', 'file', 'it is the trusted CA bundle for TLS', Severity::HIGH, null],
        ['openssl.capath', 'dir', 'it holds trusted CA certificates', Severity::HIGH, null],
        ['curl.cainfo', 'file', 'it is the trusted CA bundle for cURL', Severity::HIGH, null],
        ['soap.wsdl_cache_dir', 'dir', 'SoapClient trusts the WSDL files cached there', Severity::MEDIUM, Severity::MEDIUM],
        ['sqlite3.extension_dir', 'dir', 'SQLite3::loadExtension() loads native code from it', Severity::HIGH,
            Severity::HIGH],
        ['sendmail_path', 'command', 'mail() executes it', Severity::CRITICAL, null],
        ['xdebug.output_dir', 'dir', 'it receives profiler and trace dumps', null, Severity::MEDIUM],
        ['xdebug.log', 'log', 'it receives Xdebug logs', null, Severity::MEDIUM],
    ];

    /** @return list<string> */
    public static function splitPathList(string $value): array
    {
        $separator = preg_match(self::WINDOWS_LIST, $value) ? ';' : ':';
        $entries = [];
        foreach (explode($separator, $value) as $entry) {
            if (trim($entry) !== '') {
                $entries[] = trim($entry);
            }
        }
        return $entries;
    }

    /** session.save_path accepts "N;MODE;/path"; the directory is the last segment. */
    public static function sessionDir(string $value): string
    {
        $separator = strrpos($value, ';');
        return trim($separator === false ? $value : substr($value, $separator + 1));
    }

    /**
     * Absolute paths named by the configuration.
     * @return \Generator<array{array, \PhpIniAudit\Setting|\PhpIniAudit\Directive, string}> [spec, evidence, path]
     */
    public static function configuredPaths(Context $ctx): \Generator
    {
        foreach (self::PATH_SPECS as $spec) {
            [$directive, $kind] = $spec;
            $setting = $ctx->get($directive);
            $value = $setting->text();
            if ($value === '' || $setting->unresolved()) {
                continue;
            }
            if ($kind === 'list') {
                $candidates = self::splitPathList($value);
            } elseif ($kind === 'session') {
                $candidates = [self::sessionDir($value)];
            } elseif ($kind === 'command') {
                $candidates = array_slice(Execution::splitWhitespace($value), 0, 1);
            } elseif ($kind === 'log' && strtolower($value) === 'syslog') {
                continue;
            } else {
                $candidates = [$value];
            }
            foreach ($candidates as $path) {
                if ($path !== '' && Paths::isAbsolute($path)) {
                    yield [$spec, $setting, $path];
                }
            }
        }
        foreach ($ctx->config->extensions as $directive) {
            if (Paths::isAbsolute($directive->value)) {
                $spec = [$directive->name, 'file', 'it is loaded as a native extension', Severity::CRITICAL,
                    Severity::HIGH];
                yield [$spec, $directive, $directive->value];
            }
        }
    }

    public static function register(): void
    {
        Registry::rule('FS-001', 'open_basedir is not set', [
            'severity' => Severity::MEDIUM,
            'directives' => ['open_basedir'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-22',
            'description' => 'Without open_basedir, a path traversal or file-inclusion bug can reach any file the PHP '
                . 'user can read (/etc/passwd, other sites, keys). PHP does not treat it as a hard security boundary, '
                . 'but it limits the impact of common bugs.',
            'recommendation' => 'Set open_basedir to the application directory plus its temp/session/upload '
                . 'directories, each with a trailing slash.',
            'references' => ['https://www.php.net/manual/en/ini.core.php#ini.open-basedir'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('open_basedir');
            if ($setting->text() === '') {
                yield new Hit('open_basedir is empty', [$setting], null, Confidence::MEDIUM);
            }
        });

        Registry::rule('FS-002', 'open_basedir allows the whole filesystem', [
            'severity' => Severity::MEDIUM,
            'directives' => ['open_basedir'],
            'cwe' => 'CWE-22',
            'description' => "An open_basedir entry of '/' (or a bare drive) disables the restriction entirely.",
            'recommendation' => 'List only the directories the application needs.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('open_basedir');
            $broad = array_values(array_filter(self::splitPathList($setting->text()), static function (string $e): bool {
                return in_array($e, ['/', '\\'], true) || preg_match('/^[A-Za-z]:[\\\\\/]?\z/', $e);
            }));
            if ($broad) {
                yield new Hit('open_basedir contains ' . Base::names($broad), [$setting]);
            }
        });

        Registry::rule('FS-003', 'open_basedir entries match by prefix', [
            'severity' => Severity::LOW,
            'directives' => ['open_basedir'],
            'cwe' => 'CWE-22',
            'description' => "open_basedir compares prefixes: '/var/www/site' also allows '/var/www/site-backup'. A "
                . 'trailing separator restricts the entry to that directory.',
            'recommendation' => "End every directory entry with '/' (or '\\' on Windows).",
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('open_basedir');
            $loose = array_values(array_filter(self::splitPathList($setting->text()), static function (string $e): bool {
                return Paths::isAbsolute($e) && !Util::endsWith($e, '/') && !Util::endsWith($e, '\\')
                    && !in_array($e, ['/', '\\'], true);
            }));
            if ($loose) {
                yield new Hit('entries without trailing separator: ' . Base::names($loose), [$setting]);
            }
        });

        Registry::rule('FS-004', 'open_basedir uses relative entries', [
            'severity' => Severity::LOW,
            'directives' => ['open_basedir'],
            'cwe' => 'CWE-22',
            'description' => "Relative entries such as '.' are resolved against the current working directory, which "
                . 'changes with chdir() and the requested script.',
            'recommendation' => 'Use absolute directories only.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('open_basedir');
            $relative = array_values(array_filter(self::splitPathList($setting->text()), static function (string $e): bool {
                return !Paths::isAbsolute($e);
            }));
            if ($relative) {
                yield new Hit('relative entries: ' . Base::names($relative), [$setting]);
            }
        });

        Registry::rule('FS-005', 'Security-relevant path is world-writable', [
            'severity' => Severity::HIGH,
            'scope' => 'config',
            'cwe' => 'CWE-732',
            'description' => 'A path PHP loads code, certificates, sessions or logs from is writable by every local '
                . 'user, or sits in a world-writable directory where it can be created or replaced.',
            'recommendation' => 'Make the path owned by root (or the deploy user) and not writable by others; use a '
                . 'dedicated directory instead of /tmp.',
        ], static function (Context $ctx): iterable {
            if ($ctx->paths === null) {
                return;
            }
            foreach (self::configuredPaths($ctx) as [$spec, $setting, $path]) {
                [, , $purpose, $writable] = $spec;
                if ($writable === null) {
                    continue;
                }
                $facts = $ctx->paths->facts($path);
                if ($facts === null) {
                    continue;
                }
                $label = "{$setting->name} path $path";
                $defaultValue = $setting instanceof Setting && !$setting->isSet();
                if ($facts->worldWritable) {
                    $sticky = $facts->sticky ? ' (sticky)' : '';
                    yield new Hit("$label is world-writable$sticky; $purpose", [$setting], $writable,
                        $defaultValue ? Confidence::LOW : Confidence::HIGH);
                } elseif ($facts->writableAncestor !== null && $facts->writableAncestor !== '') {
                    $state = !$facts->exists ? 'does not exist' : 'exists';
                    $replaceable = !$facts->writableAncestorSticky || !$facts->exists;
                    if ($replaceable) {
                        yield new Hit("$label $state in world-writable {$facts->writableAncestor}; $purpose", [$setting],
                            $writable, $defaultValue ? Confidence::LOW : Confidence::MEDIUM);
                    }
                }
            }
        });

        Registry::rule('FS-006', 'Sensitive path inside a web-served directory', [
            'severity' => Severity::HIGH,
            'cwe' => 'CWE-538',
            'description' => 'Logs, sessions, uploads or caches under the document root can be downloaded, and log or '
                . 'session files that are both web-reachable and includable enable log-poisoning attacks.',
            'recommendation' => 'Move the path outside the document root. Pass --webroot to make this check exact.',
        ], static function (Context $ctx): iterable {
            if ($ctx->paths === null) {
                return;
            }
            foreach (self::configuredPaths($ctx) as [$spec, $setting, $path]) {
                [, , $purpose, , $webroot] = $spec;
                if ($webroot === null) {
                    continue;
                }
                $confidence = $ctx->paths->webrootMatch($path);
                if ($confidence !== null) {
                    yield new Hit("{$setting->name} path $path appears to be web-served; $purpose", [$setting],
                        $webroot, $confidence);
                }
            }
        });

        Registry::rule('FS-007', 'Configured path does not exist', [
            'severity' => Severity::INFO,
            'description' => 'An explicitly configured path does not exist on the audited system; PHP silently falls '
                . 'back or fails at runtime, and whoever creates the path first controls it.',
            'recommendation' => 'Create the path with the intended owner and permissions, or remove the directive.',
        ], static function (Context $ctx): iterable {
            if ($ctx->paths === null) {
                return;
            }
            foreach (self::configuredPaths($ctx) as [, $setting, $path]) {
                if ($setting instanceof Setting && !$setting->isSet()) {
                    continue;
                }
                $facts = $ctx->paths->facts($path);
                if ($facts !== null && !$facts->exists
                    && ($facts->writableAncestor === null || $facts->writableAncestor === '')) {
                    yield new Hit("{$setting->name} path $path does not exist", [$setting]);
                }
            }
        });

        Registry::rule('FS-008', 'Per-directory .user.ini overrides enabled', [
            'severity' => Severity::INFO,
            'directives' => ['user_ini.filename'],
            'sapis' => Base::FASTCGI_SAPIS,
            'cwe' => 'CWE-15',
            'description' => 'With CGI/FastCGI, any directory may carry a .user.ini that changes PERDIR settings such '
                . 'as auto_prepend_file. An upload vulnerability then becomes persistent code execution.',
            'recommendation' => 'Set user_ini.filename = (empty) if applications do not need per-directory settings.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('user_ini.filename');
            if ($setting->text() !== '') {
                yield new Hit('per-directory overrides read from ' . Util::repr($setting->text()), [$setting]);
            }
        });

        Registry::rule('FS-009', 'HTTP file uploads enabled', [
            'severity' => Severity::INFO,
            'directives' => ['file_uploads'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-434',
            'description' => 'file_uploads lets every script receive files; disable it on hosts that never accept '
                . 'uploads.',
            'recommendation' => 'Set file_uploads = Off where uploads are not needed.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('file_uploads');
            if ($setting->asBool()) {
                yield new Hit('file_uploads is On', [$setting], null, Confidence::LOW);
            }
        });

        Registry::rule('FS-010', 'Uploads stored in the shared system temp directory', [
            'severity' => Severity::INFO,
            'directives' => ['upload_tmp_dir', 'file_uploads'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-377',
            'description' => 'Without upload_tmp_dir, uploads land in the system temp directory shared with every '
                . 'other process, which eases temp-file races and LFI-via-upload techniques.',
            'recommendation' => 'Point upload_tmp_dir at a dedicated directory owned by the PHP user, mode 0700.',
        ], static function (Context $ctx): iterable {
            $uploads = $ctx->get('file_uploads');
            $setting = $ctx->get('upload_tmp_dir');
            if ($uploads->asBool() && $setting->text() === '') {
                yield new Hit('upload_tmp_dir is not set', [$setting]);
            }
        });

        Registry::rule('FS-011', 'Configuration file writable by other users', [
            'severity' => Severity::CRITICAL,
            'scope' => 'file',
            'cwe' => 'CWE-732',
            'description' => 'Anyone who can write a PHP configuration file or its directory can enable '
                . 'auto_prepend_file, load extensions or disable protections.',
            'recommendation' => 'Make configuration files and their directories owned by root and not writable by '
                . 'group or others.',
        ], static function (FileContext $fctx): iterable {
            if ($fctx->paths === null) {
                return;
            }
            $facts = $fctx->paths->facts($fctx->path());
            if ($facts === null || !$facts->exists) {
                return;
            }
            if ($facts->worldWritable) {
                yield new Hit("{$fctx->path()} is world-writable");
            } elseif ($facts->writableAncestor !== null && $facts->writableAncestor !== ''
                && !$facts->writableAncestorSticky) {
                yield new Hit("{$fctx->path()} is in world-writable directory {$facts->writableAncestor}");
            } elseif ($facts->groupWritable) {
                yield new Hit("{$fctx->path()} is group-writable", [], Severity::LOW, Confidence::MEDIUM);
            }
        });
    }
}

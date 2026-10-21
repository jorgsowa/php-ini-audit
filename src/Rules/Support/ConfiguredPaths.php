<?php

namespace PhpIniAudit\Rules\Support;

use PhpIniAudit\Directive;
use PhpIniAudit\Paths;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Setting;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

/** Absolute paths named by the configuration, for the filesystem rules that stat them. */
final class ConfiguredPaths
{
    /** [directive, kind, purpose, severity when writable, severity when web-served] */
    public const SPECS = [
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

    /** @return \Generator<array{array, Setting|Directive, string}> [spec, evidence, path] */
    public static function in(Context $ctx): \Generator
    {
        foreach (self::SPECS as $spec) {
            [$directive, $kind] = $spec;
            $setting = $ctx->get($directive);
            $value = $setting->text();
            if ($value === '' || $setting->unresolved()) {
                continue;
            }
            if ($kind === 'list') {
                $candidates = Values::splitPathList($value);
            } elseif ($kind === 'session') {
                $candidates = [Values::sessionDir($value)];
            } elseif ($kind === 'command') {
                $candidates = array_slice(Values::splitWhitespace($value), 0, 1);
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
}

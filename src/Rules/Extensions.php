<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Directive;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

/** Debug extensions, OPcache, database drivers and character encoding. */
final class Extensions
{
    public const DEV_EXTENSIONS = ['xhprof', 'tideways', 'tideways_xhprof', 'pcov', 'uopz', 'runkit', 'runkit7', 'spx'];
    public const CREDENTIAL_DIRECTIVES = [
        'mysqli.default_pw',
        'mysql.default_password',
        'odbc.default_pw',
        'ibase.default_password',
        'pdo_odbc.default_pw',
    ];
    private const CREDENTIAL_NAME = '/(^|[._])(pw|pass|passwd|password|secret)$/i';
    private const MULTIBYTE_RISK = '/^(gbk|gb2312|gb18030|big5(-hkscs)?|sjis|shift[_-]?jis|cp932|cp936|cp949|cp950|euc-?jp-?ms)$/i';

    public static function loadedExtension(Context $ctx, string $name): ?Directive
    {
        foreach ($ctx->config->extensions as $directive) {
            $path = str_replace('\\', '/', $directive->value);
            $slash = strrpos($path, '/');
            $base = strtolower($slash === false ? $path : substr($path, $slash + 1));
            $stem = preg_replace('/^(php_)?|(\.so|\.dll)$/', '', $base);
            if ($stem === $name) {
                return $directive;
            }
        }
        return null;
    }

    private static function xdebugSettingsPresent(Context $ctx): bool
    {
        foreach ($ctx->config->explicit() as $setting) {
            if (Util::startsWith($setting->name, 'xdebug.')) {
                return true;
            }
        }
        return false;
    }

    public static function register(): void
    {
        Registry::rule('EXT-001', 'Xdebug accepts debugger connections for any client', [
            'severity' => Severity::CRITICAL,
            'dev_severity' => Severity::HIGH,
            'directives' => ['xdebug.mode', 'xdebug.discover_client_host', 'xdebug.remote_enable',
                'xdebug.remote_connect_back'],
            'cwe' => 'CWE-489',
            'description' => 'With discover_client_host (Xdebug 3) or remote_connect_back (Xdebug 2), Xdebug connects '
                . 'back to whoever sent the request and hands them a debugger that can evaluate arbitrary PHP.',
            'recommendation' => 'Never enable client discovery on reachable hosts; remove Xdebug from production.',
            'references' => ['https://xdebug.org/docs/all_settings#discover_client_host'],
        ], static function (Context $ctx): iterable {
            if (!(self::loadedExtension($ctx, 'xdebug') !== null || self::xdebugSettingsPresent($ctx))) {
                return;
            }
            $mode = $ctx->get('xdebug.mode');
            $discover = $ctx->get('xdebug.discover_client_host');
            $modes = array_map('trim', explode(',', strtolower($mode->text())));
            if (in_array('debug', $modes, true) && $discover->asBool()) {
                yield new Hit('xdebug.mode includes debug with discover_client_host = 1', [$mode, $discover]);
            }
            $remote = $ctx->get('xdebug.remote_enable');
            $connectBack = $ctx->get('xdebug.remote_connect_back');
            if ($remote->asBool() && $connectBack->asBool()) {
                yield new Hit('xdebug.remote_enable with remote_connect_back = 1 (Xdebug 2)', [$remote, $connectBack]);
            }
        });

        Registry::rule('EXT-002', 'Xdebug loaded', [
            'severity' => Severity::HIGH,
            'dev_severity' => Severity::INFO,
            'directives' => ['zend_extension', 'xdebug.mode'],
            'cwe' => 'CWE-489',
            'description' => 'Xdebug in production slows every request and, depending on xdebug.mode, exposes '
                . 'debugging, tracing and profiling output.',
            'recommendation' => 'Do not install Xdebug on production systems.',
        ], static function (Context $ctx): iterable {
            $directive = self::loadedExtension($ctx, 'xdebug');
            if ($directive === null) {
                return;
            }
            $mode = $ctx->get('xdebug.mode');
            if (strtolower($mode->text()) === 'off') {
                yield new Hit('Xdebug is loaded with xdebug.mode = off', [$directive, $mode], Severity::LOW);
            } else {
                yield new Hit("Xdebug is loaded ({$mode->describe()})", [$directive, $mode]);
            }
        });

        Registry::rule('EXT-003', 'Development or profiling extension loaded', [
            'severity' => Severity::LOW,
            'production_only' => true,
            'directives' => ['extension', 'zend_extension'],
            'cwe' => 'CWE-489',
            'description' => 'Profilers, coverage drivers and runtime-patching extensions (uopz, runkit) are not meant '
                . 'for production and can change behaviour or leak data.',
            'recommendation' => 'Remove development extensions from production images.',
        ], static function (Context $ctx): iterable {
            foreach (self::DEV_EXTENSIONS as $name) {
                $directive = self::loadedExtension($ctx, $name);
                if ($directive !== null) {
                    yield new Hit("$name is loaded", [$directive]);
                }
            }
        });

        Registry::rule('OPC-001', 'OPcache file cache enabled', [
            'severity' => Severity::MEDIUM,
            'directives' => ['opcache.file_cache'],
            'cwe' => 'CWE-494',
            'description' => 'Compiled scripts in opcache.file_cache are executed without re-reading the source. '
                . 'Anyone who can write there (or an arbitrary-file-write bug) can plant opcodes and get code execution.',
            'recommendation' => 'Disable the file cache, or keep it in a root-owned directory the PHP user cannot '
                . 'write except through OPcache.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('opcache.file_cache');
            if ($setting->text() !== '') {
                yield new Hit($setting->describe(), [$setting], $ctx->isWeb() ? Severity::MEDIUM : Severity::LOW);
            }
        });

        Registry::rule('OPC-002', 'OPcache API not restricted', [
            'severity' => Severity::LOW,
            'directives' => ['opcache.restrict_api'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-284',
            'description' => 'Any script can call opcache_get_status() (revealing every cached path) or '
                . 'opcache_reset(). This matters on shared hosting.',
            'recommendation' => 'Set opcache.restrict_api to the path prefix of trusted admin scripts.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('opcache.restrict_api');
            if ($setting->text() === '') {
                yield new Hit('opcache.restrict_api is empty', [$setting], null, Confidence::LOW);
            }
        });

        Registry::rule('OPC-003', 'OPcache does not isolate users', [
            'severity' => Severity::INFO,
            'directives' => ['opcache.validate_permission', 'opcache.validate_root'],
            'sapis' => Base::FASTCGI_SAPIS,
            'cwe' => 'CWE-653',
            'description' => "On shared hosting without validate_permission/validate_root, one user's scripts may hit "
                . "another user's cached files.",
            'recommendation' => 'Enable opcache.validate_permission (and validate_root with chroot) on multi-tenant '
                . 'hosts.',
        ], static function (Context $ctx): iterable {
            $off = array_values(array_filter(['opcache.validate_permission', 'opcache.validate_root'],
                static function (string $n) use ($ctx): bool {
                    return !$ctx->on($n);
                }));
            if ($off) {
                yield new Hit(Base::names($off) . ' Off', array_map([$ctx, 'get'], $off), null, Confidence::LOW);
            }
        });

        Registry::rule('DB-001', 'MySQL LOAD DATA LOCAL enabled', [
            'severity' => Severity::MEDIUM,
            'directives' => ['mysqli.allow_local_infile'],
            'cwe' => 'CWE-73',
            'description' => 'A malicious or spoofed MySQL server can ask the client to send any local file the PHP '
                . 'user can read.',
            'recommendation' => 'Set mysqli.allow_local_infile = Off, or restrict mysqli.local_infile_directory.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('mysqli.allow_local_infile');
            if ($setting->asBool()) {
                yield new Hit('mysqli.allow_local_infile is On', [$setting]);
            }
        });

        Registry::rule('DB-002', 'Credentials stored in PHP configuration', [
            'severity' => Severity::MEDIUM,
            'directives' => self::CREDENTIAL_DIRECTIVES,
            'cwe' => 'CWE-260',
            'description' => 'Default passwords in INI files are readable by every user that can read the '
                . 'configuration and are printed by phpinfo() and ini_get_all().',
            'recommendation' => "Pass credentials from the application's secret storage instead.",
        ], static function (Context $ctx): iterable {
            foreach ($ctx->config->explicit() as $setting) {
                if ($setting->text() !== '' && (in_array($setting->name, self::CREDENTIAL_DIRECTIVES, true)
                    || preg_match(self::CREDENTIAL_NAME, $setting->name))) {
                    yield new Hit("{$setting->name} holds a value", [$setting]);
                }
            }
        });

        Registry::rule('DB-003', 'SQLite safety features relaxed', [
            'severity' => Severity::LOW,
            'directives' => ['sqlite3.defensive', 'sqlite3.extension_dir'],
            'cwe' => 'CWE-114',
            'description' => 'sqlite3.defensive = Off allows SQL to corrupt the database file; sqlite3.extension_dir '
                . 'enables SQLite3::loadExtension(), which loads native code.',
            'recommendation' => 'Keep sqlite3.defensive = On and leave sqlite3.extension_dir unset.',
        ], static function (Context $ctx): iterable {
            $defensive = $ctx->get('sqlite3.defensive');
            if (!$defensive->asBool()) {
                yield new Hit('sqlite3.defensive is Off', [$defensive]);
            }
            $extensionDir = $ctx->get('sqlite3.extension_dir');
            if ($extensionDir->text() !== '') {
                yield new Hit("{$extensionDir->describe()} enables loadExtension()", [$extensionDir]);
            }
        });

        Registry::rule('ENC-001', 'Unsafe default character set', [
            'severity' => Severity::MEDIUM,
            'directives' => ['default_charset'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-838',
            'description' => 'Multi-byte charsets such as GBK, Big5 or Shift_JIS let a trailing byte swallow escape '
                . 'characters (addslashes/escaping bypass, SQL injection); an empty charset leaves browsers guessing '
                . '(XSS).',
            'recommendation' => 'Set default_charset = "UTF-8".',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('default_charset');
            $charset = $setting->text();
            if ($charset === '') {
                yield new Hit('default_charset is empty', [$setting], Severity::LOW);
            } elseif (preg_match(self::MULTIBYTE_RISK, $charset)) {
                yield new Hit("default_charset = $charset", [$setting]);
            } elseif (!in_array(str_replace('_', '-', strtoupper($charset)), ['UTF-8', 'UTF8'], true)) {
                yield new Hit("default_charset = $charset", [$setting], Severity::LOW);
            }
        });

        Registry::rule('ENC-002', 'mbstring function overloading enabled', [
            'severity' => Severity::MEDIUM,
            'directives' => ['mbstring.func_overload'],
            'cwe' => 'CWE-704',
            'description' => 'mbstring.func_overload silently changes strlen()/substr() into multibyte versions, '
                . 'breaking binary-safe code such as cryptography and length checks. Removed in PHP 8.0.',
            'recommendation' => 'Set mbstring.func_overload = 0 and call mb_* functions explicitly.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('mbstring.func_overload');
            if ($setting->asInt() === 0) {
                return;
            }
            $below8 = $ctx->versionBelow(8, 0);
            if ($below8 === false) {
                return;
            }
            yield new Hit($setting->describe(), [$setting], null, $below8 ? Confidence::HIGH : Confidence::LOW);
        });

        Registry::rule('ENC-003', 'Multibyte script parsing enabled', [
            'severity' => Severity::LOW,
            'directives' => ['zend.multibyte'],
            'cwe' => 'CWE-838',
            'description' => 'zend.multibyte lets scripts be parsed in non-ASCII-compatible encodings such as '
                . 'Shift_JIS, which complicates reviewing code and can hide payloads.',
            'recommendation' => 'Set zend.multibyte = Off unless legacy encodings are required.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('zend.multibyte');
            if ($setting->asBool()) {
                yield new Hit('zend.multibyte is On', [$setting]);
            }
        });

        Registry::rule('ENC-004', 'Automatic input encoding translation', [
            'severity' => Severity::LOW,
            'directives' => ['mbstring.encoding_translation'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-838',
            'description' => 'mbstring.encoding_translation converts request input before the application validates '
                . 'it, which can undo validation done on raw bytes.',
            'recommendation' => 'Set mbstring.encoding_translation = Off and convert explicitly.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('mbstring.encoding_translation');
            if ($setting->asBool()) {
                yield new Hit('mbstring.encoding_translation is On', [$setting]);
            }
        });
    }
}

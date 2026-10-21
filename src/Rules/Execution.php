<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

/** Settings that enable or widen code and command execution paths. */
final class Execution
{
    public const EXEC_FUNCTIONS = ['exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen', 'pcntl_exec'];
    public const MAIL_LAUNCHERS = ['mail', 'mb_send_mail', 'imap_mail', 'error_log'];
    private const STREAM_WRAPPER = '/^\s*(?:([a-z][a-z0-9+.\-]*):\/\/|data:)/i';
    private const SENDMAIL_DANGER = '/(?:^|\s)(-X|-O|-C|-be)\S*/';
    private const WINDOWS_ABSOLUTE = '/^[A-Za-z]:[\\\\\/]/';

    /** @return array<string, true> lower-cased names in disable_functions */
    public static function disabledFunctions(Context $ctx): array
    {
        $disabled = [];
        foreach ($ctx->get('disable_functions')->asList() as $name) {
            $disabled[strtolower($name)] = true;
        }
        return $disabled;
    }

    public static function register(): void
    {
        Registry::rule('EXEC-001', 'Remote file inclusion enabled', [
            'severity' => Severity::CRITICAL,
            'directives' => ['allow_url_include', 'allow_url_fopen'],
            'cwe' => 'CWE-98',
            'description' => 'allow_url_include lets include/require load code from http://, ftp:// and data:// URLs, '
                . 'turning any file-inclusion bug into remote code execution.',
            'recommendation' => 'Set allow_url_include = Off. The directive has been deprecated since PHP 7.4.',
            'references' => ['https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('allow_url_include');
            if (!$setting->asBool()) {
                return;
            }
            $fopen = $ctx->get('allow_url_fopen');
            if ($fopen->asBool()) {
                yield new Hit('allow_url_include is enabled', [$setting]);
            } else {
                yield new Hit(
                    'allow_url_include is enabled; allow_url_fopen = Off blocks remote wrappers today, '
                    . 'but a single change re-enables remote inclusion',
                    [$setting, $fopen],
                    Severity::HIGH
                );
            }
        });

        Registry::rule('EXEC-002', 'Remote URLs accepted by file functions', [
            'severity' => Severity::MEDIUM,
            'directives' => ['allow_url_fopen'],
            'cwe' => 'CWE-918',
            'description' => 'allow_url_fopen lets fopen(), file_get_contents(), getimagesize() and friends fetch '
                . 'http:// and ftp:// URLs, which turns user-controlled paths into server-side request forgery.',
            'recommendation' => 'Set allow_url_fopen = Off and use an HTTP client (cURL) with explicit allow-lists '
                . 'where remote fetches are needed.',
            'references' => ['https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('allow_url_fopen');
            if ($setting->asBool()) {
                yield new Hit('allow_url_fopen is enabled', [$setting], $ctx->isWeb() ? Severity::MEDIUM : Severity::LOW,
                    Confidence::MEDIUM);
            }
        });

        Registry::rule('EXEC-003', 'Auto-prepended/appended file loaded through a stream wrapper', [
            'severity' => Severity::CRITICAL,
            'directives' => ['auto_prepend_file', 'auto_append_file'],
            'cwe' => 'CWE-94',
            'description' => 'auto_prepend_file/auto_append_file pointing at php://input, data:, http:// or another '
                . 'wrapper executes request- or network-supplied code on every request; this is a classic FastCGI '
                . 'exploitation payload.',
            'recommendation' => 'Remove the directive or point it at a root-owned local file.',
        ], static function (Context $ctx): iterable {
            foreach (['auto_prepend_file', 'auto_append_file'] as $name) {
                $setting = $ctx->get($name);
                if (preg_match(self::STREAM_WRAPPER, $setting->text(), $match)
                    && strtolower($match[1] ?? '') !== 'file') {
                    yield new Hit("{$setting->describe()} loads code through a stream wrapper", [$setting]);
                }
            }
        });

        Registry::rule('EXEC-004', 'Code automatically prepended or appended to every script', [
            'severity' => Severity::INFO,
            'directives' => ['auto_prepend_file', 'auto_append_file'],
            'cwe' => 'CWE-506',
            'description' => 'auto_prepend_file/auto_append_file run a file before/after every script. Security '
                . 'plugins use it legitimately, but a value set from .user.ini or .htaccess is a common web-shell '
                . 'persistence technique.',
            'recommendation' => 'Confirm the file is expected, root-owned and not writable by the PHP user; set '
                . 'user_ini.filename = to stop per-directory overrides if they are not needed.',
        ], static function (Context $ctx): iterable {
            foreach (['auto_prepend_file', 'auto_append_file'] as $name) {
                $setting = $ctx->get($name);
                $value = $setting->text();
                if ($value === '' || strtolower($value) === 'none' || preg_match(self::STREAM_WRAPPER, $value)) {
                    continue;
                }
                if (Base::overlaySet($setting)) {
                    yield new Hit(
                        "{$setting->describe()} is set from a per-directory file ({$setting->directive->kind})",
                        [$setting],
                        Severity::MEDIUM,
                        Confidence::LOW
                    );
                } elseif (!Util::startsWith($value, '/') && !preg_match(self::WINDOWS_ABSOLUTE, $value)) {
                    yield new Hit(
                        "{$setting->describe()} is a relative path resolved through include_path and the working "
                        . 'directory',
                        [$setting],
                        Severity::LOW
                    );
                } else {
                    yield new Hit("{$setting->describe()} runs for every request", [$setting]);
                }
            }
        });

        Registry::rule('EXEC-005', 'Command execution functions are available', [
            'severity' => Severity::MEDIUM,
            'directives' => ['disable_functions'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-78',
            'description' => 'Functions that spawn processes turn code injection, deserialization gadgets and file '
                . 'uploads into full operating-system command execution.',
            'recommendation' => 'List the functions the application does not use in disable_functions (php.ini or '
                . 'php_admin_value in the FPM pool). Composer and symfony/process need proc_open.',
            'references' => ['https://www.php.net/manual/en/ini.core.php#ini.disable-functions'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('disable_functions');
            $disabled = self::disabledFunctions($ctx);
            $available = array_values(array_filter(self::EXEC_FUNCTIONS, static function (string $f) use ($disabled): bool {
                return !isset($disabled[$f]);
            }));
            if (!$available) {
                return;
            }
            if (count($available) === count(self::EXEC_FUNCTIONS)) {
                $message = 'no command-execution function is disabled (' . Base::names($available) . ')';
            } else {
                $message = 'disable_functions is partial; still callable: ' . Base::names($available);
            }
            yield new Hit($message, [$setting], null, Confidence::MEDIUM);
        });

        Registry::rule('EXEC-006', 'disable_functions can be bypassed', [
            'severity' => Severity::MEDIUM,
            'directives' => ['disable_functions'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-693',
            'description' => 'With every exec-style function disabled, putenv() combined with a function that '
                . 'launches sendmail lets an attacker set LD_PRELOAD and run native code anyway.',
            'recommendation' => 'Also disable putenv and the mail launchers that are not needed, or run PHP with a '
                . 'seccomp/AppArmor profile instead of relying on disable_functions.',
            'references' => ['https://www.php.net/manual/en/function.putenv.php'],
        ], static function (Context $ctx): iterable {
            $disabled = self::disabledFunctions($ctx);
            foreach (self::EXEC_FUNCTIONS as $function) {
                if (!isset($disabled[$function])) {
                    return;
                }
            }
            $launchers = array_values(array_filter(self::MAIL_LAUNCHERS, static function (string $f) use ($disabled): bool {
                return !isset($disabled[$f]);
            }));
            if (!isset($disabled['putenv']) && $launchers) {
                yield new Hit(
                    'putenv() and ' . Base::names($launchers) . ' remain callable (LD_PRELOAD bypass)',
                    [$ctx->get('disable_functions')],
                    null,
                    Confidence::MEDIUM
                );
            }
        });

        Registry::rule('EXEC-007', 'FFI available to every script', [
            'severity' => Severity::HIGH,
            'directives' => ['ffi.enable'],
            'cwe' => 'CWE-749',
            'description' => 'ffi.enable = On lets any script call arbitrary C functions, which bypasses '
                . 'disable_functions, open_basedir and every other PHP-level restriction.',
            'recommendation' => 'Use ffi.enable = preload (the default) so that only preloaded code can use FFI.',
            'references' => ['https://www.php.net/manual/en/ffi.configuration.php'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('ffi.enable');
            if (strtolower($setting->text()) !== 'preload' && $setting->asBool()) {
                yield new Hit('ffi.enable allows FFI from any script', [$setting], null, Confidence::MEDIUM);
            }
        });

        Registry::rule('EXEC-008', 'Runtime extension loading (dl) enabled', [
            'severity' => Severity::LOW,
            'directives' => ['enable_dl'],
            'cwe' => 'CWE-114',
            'description' => 'enable_dl permits dl() to load shared objects at runtime. dl() is only available to the '
                . 'CLI and embed SAPIs, so the impact is limited to scripts run from the command line.',
            'recommendation' => 'Set enable_dl = Off.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('enable_dl');
            if ($setting->asBool()) {
                yield new Hit('enable_dl is enabled', [$setting], null,
                    $ctx->sapi === 'cli' ? Confidence::HIGH : Confidence::MEDIUM);
            }
        });

        Registry::rule('EXEC-009', 'Phar archives writable at runtime', [
            'severity' => Severity::MEDIUM,
            'directives' => ['phar.readonly'],
            'cwe' => 'CWE-502',
            'description' => 'phar.readonly = Off allows scripts to create and modify Phar archives, which helps '
                . 'attackers craft polyglot files for phar:// deserialization and code execution.',
            'recommendation' => 'Set phar.readonly = On except on build machines.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('phar.readonly');
            if (!$setting->asBool()) {
                yield new Hit('phar.readonly is Off', [$setting], $ctx->isWeb() ? Severity::MEDIUM : Severity::LOW);
            }
        });

        Registry::rule('EXEC-010', 'Unsigned Phar archives accepted', [
            'severity' => Severity::LOW,
            'directives' => ['phar.require_hash'],
            'cwe' => 'CWE-345',
            'description' => 'phar.require_hash = Off lets PHP open Phar archives without a signature.',
            'recommendation' => 'Set phar.require_hash = On.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('phar.require_hash');
            if (!$setting->asBool()) {
                yield new Hit('phar.require_hash is Off', [$setting]);
            }
        });

        Registry::rule('EXEC-011', 'Query string exposed as $argv in web requests', [
            'severity' => Severity::MEDIUM,
            'directives' => ['register_argc_argv'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-88',
            'description' => 'register_argc_argv = On fills $argv from the query string in web requests. Combined '
                . 'with a local file inclusion this enables the pearcmd.php remote-code-execution technique; it is On '
                . 'by default when no php.ini is loaded (e.g. official Docker images).',
            'recommendation' => 'Set register_argc_argv = Off for web SAPIs.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('register_argc_argv');
            if ($setting->asBool()) {
                yield new Hit('register_argc_argv is On for a web SAPI', [$setting]);
            }
        });

        Registry::rule('EXEC-012', 'imap_open() may run rsh/ssh commands', [
            'severity' => Severity::HIGH,
            'directives' => ['imap.enable_insecure_rsh'],
            'cwe' => 'CWE-78',
            'description' => 'imap.enable_insecure_rsh lets imap_open() mailbox names inject arguments into rsh/ssh '
                . '(CVE-2018-19518).',
            'recommendation' => 'Set imap.enable_insecure_rsh = Off.',
            'references' => ['https://nvd.nist.gov/vuln/detail/CVE-2018-19518'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('imap.enable_insecure_rsh');
            if ($setting->asBool()) {
                yield new Hit('imap.enable_insecure_rsh is On', [$setting]);
            }
        });

        Registry::rule('EXEC-013', 'Dangerous sendmail options configured', [
            'severity' => Severity::HIGH,
            'directives' => ['sendmail_path', 'mail.force_extra_parameters'],
            'cwe' => 'CWE-88',
            'description' => 'sendmail options such as -X (log file), -O/-C (alternate queue/config) or Exim\'s -be '
                . '(expansion test) let mail() write attacker-influenced files or evaluate expressions.',
            'recommendation' => 'Keep sendmail_path to an absolute binary with -t -i, and do not force extra '
                . 'parameters.',
        ], static function (Context $ctx): iterable {
            foreach (['sendmail_path', 'mail.force_extra_parameters'] as $name) {
                $setting = $ctx->get($name);
                preg_match_all(self::SENDMAIL_DANGER, $setting->text(), $matches);
                $flags = array_values(array_unique($matches[1]));
                sort($flags, SORT_STRING);
                if ($flags) {
                    yield new Hit("{$setting->describe()} contains " . Base::names($flags), [$setting]);
                }
            }
            $path = $ctx->get('sendmail_path');
            $binary = $path->text() !== '' ? (self::splitWhitespace($path->text())[0] ?? '') : '';
            if ($binary !== '' && !Util::startsWith($binary, '/') && !preg_match(self::WINDOWS_ABSOLUTE, $binary)) {
                yield new Hit('sendmail_path binary ' . Util::repr($binary) . ' is resolved through $PATH', [$path],
                    Severity::LOW);
            }
        });

        Registry::rule('EXEC-014', 'Assertions compiled and executed in production', [
            'severity' => Severity::LOW,
            'directives' => ['zend.assertions', 'assert.active'],
            'production_only' => true,
            'cwe' => 'CWE-489',
            'description' => 'zend.assertions = 1 executes assert() calls in production. Before PHP 8.0 string '
                . 'assertions were evaluated as code.',
            'recommendation' => 'Set zend.assertions = -1 in production.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('zend.assertions');
            if ($setting->asInt() !== 1) {
                return;
            }
            if ($ctx->versionBelow(8, 0) && $ctx->on('assert.active')) {
                yield new Hit(
                    "zend.assertions = 1 with assert.active on PHP < 8.0 (string assertions are eval'd)",
                    [$setting, $ctx->get('assert.active')],
                    Severity::MEDIUM
                );
            } else {
                yield new Hit('zend.assertions = 1', [$setting]);
            }
        });

        Registry::rule('EXEC-015', 'Callback invoked when unserialize() meets an unknown class', [
            'severity' => Severity::LOW,
            'directives' => ['unserialize_callback_func'],
            'cwe' => 'CWE-502',
            'description' => 'unserialize_callback_func is called with attacker-chosen class names while '
                . 'unserializing untrusted data, which can trigger autoloading of unexpected files.',
            'recommendation' => 'Leave unserialize_callback_func empty unless the callback is strictly validated.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('unserialize_callback_func');
            if ($setting->text() !== '') {
                yield new Hit($setting->describe(), [$setting]);
            }
        });

        Registry::rule('EXEC-016', 'include_path contains the current directory', [
            'severity' => Severity::INFO,
            'directives' => ['include_path'],
            'cwe' => 'CWE-427',
            'description' => "A '.' entry makes relative include/require resolve against the working directory, "
                . 'which may be attacker-influenced (e.g. upload directories).',
            'recommendation' => "Use absolute includes (__DIR__ . '/file.php') or remove '.' from include_path.",
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('include_path');
            $separator = preg_match('/(^|;)[A-Za-z]:[\\\\\/]/', $setting->text()) ? ';' : ':';
            if (in_array('.', array_map('trim', explode($separator, $setting->text())), true)) {
                yield new Hit("{$setting->describe()} includes '.'", [$setting]);
            }
        });

        Registry::rule('EXEC-017', 'Session upload progress writes request data into session files', [
            'severity' => Severity::LOW,
            'directives' => ['session.upload_progress.enabled', 'session.upload_progress.cleanup'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-98',
            'description' => 'With upload progress enabled, any multipart request stores attacker-controlled data in a '
                . 'session file, which turns a local file inclusion into code execution even without a session.',
            'recommendation' => 'Set session.upload_progress.enabled = Off unless upload progress bars are used; never '
                . 'disable session.upload_progress.cleanup.',
        ], static function (Context $ctx): iterable {
            $enabled = $ctx->get('session.upload_progress.enabled');
            if (!$enabled->asBool()) {
                return;
            }
            $cleanup = $ctx->get('session.upload_progress.cleanup');
            if (!$cleanup->asBool()) {
                yield new Hit(
                    'upload progress is enabled and cleanup is Off, so the data persists in the session file',
                    [$enabled, $cleanup],
                    Severity::MEDIUM
                );
            } else {
                yield new Hit('session.upload_progress.enabled is On', [$enabled], null, Confidence::MEDIUM);
            }
        });
    }

    /** Split on runs of whitespace, dropping empty items. */
    public static function splitWhitespace(string $text): array
    {
        return preg_split('/[\s\x1c-\x1f]+/', $text, -1, PREG_SPLIT_NO_EMPTY);
    }
}

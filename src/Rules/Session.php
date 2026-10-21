<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Severity;
use PhpIniAudit\Stat;
use PhpIniAudit\Util;
use PhpIniAudit\Values;

/** Session management. */
final class Session
{
    private const SHARED_TEMP = ['', '/tmp', '/var/tmp', '/dev/shm'];

    public static function register(): void
    {
        Registry::rule('SESS-001', 'Uninitialised session IDs accepted', [
            'severity' => Severity::MEDIUM,
            'directives' => ['session.use_strict_mode'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-384',
            'description' => 'Without strict mode PHP adopts any session ID a client presents, enabling session '
                . 'fixation.',
            'recommendation' => 'Set session.use_strict_mode = 1.',
            'references' => ['https://www.php.net/manual/en/session.security.ini.php'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.use_strict_mode');
            if (!$setting->asBool()) {
                yield new Hit('session.use_strict_mode is Off', [$setting]);
            }
        });

        Registry::rule('SESS-002', 'Session IDs accepted outside cookies', [
            'severity' => Severity::HIGH,
            'directives' => ['session.use_only_cookies'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-598',
            'description' => 'session.use_only_cookies = 0 accepts session IDs from the URL, enabling fixation via '
                . 'links and leaking IDs through Referer headers and logs.',
            'recommendation' => 'Set session.use_only_cookies = 1.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.use_only_cookies');
            if (!$setting->asBool()) {
                yield new Hit('session.use_only_cookies is Off', [$setting]);
            }
        });

        Registry::rule('SESS-003', 'Transparent session IDs in URLs', [
            'severity' => Severity::HIGH,
            'directives' => ['session.use_trans_sid'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-598',
            'description' => 'session.use_trans_sid rewrites links to carry the session ID, which leaks through '
                . 'Referer, browser history, proxies and shared links.',
            'recommendation' => 'Set session.use_trans_sid = 0.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.use_trans_sid');
            if ($setting->asBool()) {
                yield new Hit('session.use_trans_sid is On', [$setting]);
            }
        });

        Registry::rule('SESS-004', 'Session cookies disabled', [
            'severity' => Severity::MEDIUM,
            'directives' => ['session.use_cookies'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-598',
            'description' => 'session.use_cookies = 0 forces session IDs into URLs or breaks sessions entirely.',
            'recommendation' => 'Set session.use_cookies = 1.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.use_cookies');
            if (!$setting->asBool()) {
                yield new Hit('session.use_cookies is Off', [$setting]);
            }
        });

        Registry::rule('SESS-005', 'Session cookie readable from JavaScript', [
            'severity' => Severity::MEDIUM,
            'directives' => ['session.cookie_httponly'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-1004',
            'description' => 'Without HttpOnly, any XSS can read document.cookie and steal the session.',
            'recommendation' => 'Set session.cookie_httponly = 1.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.cookie_httponly');
            if (!$setting->asBool()) {
                yield new Hit('session.cookie_httponly is Off', [$setting]);
            }
        });

        Registry::rule('SESS-006', 'Session cookie sent over plain HTTP', [
            'severity' => Severity::MEDIUM,
            'directives' => ['session.cookie_secure'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-614',
            'description' => 'Without the Secure flag the session cookie is sent over unencrypted connections and can '
                . 'be sniffed or injected.',
            'recommendation' => 'Set session.cookie_secure = 1 on sites served over HTTPS.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.cookie_secure');
            if (!$setting->asBool()) {
                yield new Hit('session.cookie_secure is Off', [$setting], null, Confidence::MEDIUM);
            }
        });

        Registry::rule('SESS-007', 'Session cookie without SameSite protection', [
            'severity' => Severity::LOW,
            'directives' => ['session.cookie_samesite', 'session.cookie_secure'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-1275',
            'description' => 'Without SameSite=Lax or Strict the session cookie accompanies cross-site requests, '
                . 'which enables CSRF.',
            'recommendation' => 'Set session.cookie_samesite = "Lax" (or "Strict").',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.cookie_samesite');
            $value = strtolower($setting->text());
            if ($value === '') {
                if ($setting->directive !== null
                    && strtolower(trim(explode(';', $setting->directive->raw)[0])) === 'none') {
                    yield new Hit('unquoted None is parsed as an empty value; write "None" or (better) "Lax"',
                        [$setting]);
                } else {
                    yield new Hit('session.cookie_samesite is not set', [$setting]);
                }
            } elseif ($value === 'none') {
                $secure = $ctx->get('session.cookie_secure');
                if ($secure->asBool()) {
                    yield new Hit('SameSite=None sends the cookie on cross-site requests', [$setting]);
                } else {
                    yield new Hit(
                        'SameSite=None without Secure: cookie sent cross-site and rejected by modern browsers',
                        [$setting, $secure],
                        Severity::MEDIUM
                    );
                }
            } elseif (!in_array($value, ['lax', 'strict'], true)) {
                yield new Hit('unrecognised SameSite value ' . Util::repr($setting->text()), [$setting]);
            }
        });

        Registry::rule('SESS-008', 'Weak session ID entropy', [
            'severity' => Severity::HIGH,
            'directives' => ['session.sid_length', 'session.sid_bits_per_character'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-331',
            'description' => 'Session IDs need at least 128 bits of entropy (sid_length x sid_bits_per_character) to '
                . 'resist brute force.',
            'recommendation' => 'Keep sid_length >= 32 with sid_bits_per_character = 4, or use 5/6 bits per '
                . 'character.',
        ], static function (Context $ctx): iterable {
            $length = $ctx->get('session.sid_length');
            $bits = $ctx->get('session.sid_bits_per_character');
            if (!in_array($bits->asInt(), [4, 5, 6], true)) {
                return;
            }
            $entropy = max($length->asInt(), 22) * $bits->asInt();
            if ($entropy < 64) {
                yield new Hit("session IDs carry ~$entropy bits of entropy", [$length, $bits]);
            } elseif ($entropy < 128) {
                yield new Hit("session IDs carry ~$entropy bits of entropy", [$length, $bits], Severity::LOW);
            }
        });

        Registry::rule('SESS-009', 'Session files stored in a shared or listable directory', [
            'severity' => Severity::MEDIUM,
            'directives' => ['session.save_path', 'session.save_handler'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-552',
            'description' => 'Session files are named after the session ID. In a directory other users can list '
                . '(such as /tmp), they can harvest IDs and hijack sessions, or plant crafted session files.',
            'recommendation' => 'Use a dedicated session directory such as /var/lib/php/sessions with mode 1733 or '
                . '0700.',
        ], static function (Context $ctx): iterable {
            $handler = $ctx->get('session.save_handler');
            if (strtolower($handler->text()) !== 'files') {
                return;
            }
            $setting = $ctx->get('session.save_path');
            $directory = FilesAndPaths::sessionDir($setting->text());
            if ($ctx->paths !== null && Util::startsWith($directory, '/')) {
                $info = $ctx->paths->fs->stat($directory);
                if ($info !== null && ($info['mode'] & Stat::S_IROTH)) {
                    yield new Hit("$directory can be listed by every local user", [$setting]);
                    return;
                }
                if ($info !== null) {
                    return;
                }
            }
            if (in_array($directory, self::SHARED_TEMP, true)) {
                $shown = $directory !== '' ? $directory : 'the system temp directory';
                yield new Hit("session files are written to $shown", [$setting], null, Confidence::MEDIUM);
            }
        });

        Registry::rule('SESS-010', 'Session files created with permissive mode', [
            'severity' => Severity::MEDIUM,
            'directives' => ['session.save_path'],
            'cwe' => 'CWE-276',
            'description' => 'session.save_path = "N;MODE;/path" sets the file mode of session files; group or world '
                . 'access exposes session contents.',
            'recommendation' => 'Use mode 600 (the default).',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.save_path');
            $parts = explode(';', $setting->text());
            if (count($parts) !== 3) {
                return;
            }
            $shown = trim($parts[1]);
            $mode = Values::parseOctal($shown);
            if ($mode === null) {
                return;
            }
            if ($mode & 0007) {
                yield new Hit("session files are created with mode $shown", [$setting]);
            } elseif ($mode & 0070) {
                yield new Hit("session files are created with mode $shown", [$setting], Severity::LOW);
            }
        });

        Registry::rule('SESS-011', 'Long-lived sessions', [
            'severity' => Severity::LOW,
            'directives' => ['session.gc_maxlifetime'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-613',
            'description' => 'Session data is kept for gc_maxlifetime seconds of inactivity; long lifetimes widen the '
                . 'window for stolen session IDs.',
            'recommendation' => 'Keep session.gc_maxlifetime at a few hours or less and implement absolute timeouts '
                . 'in the application.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.gc_maxlifetime');
            if ($setting->asInt() > 86400) {
                yield new Hit("{$setting->describe()} seconds (> 1 day)", [$setting]);
            }
        });

        Registry::rule('SESS-012', 'Default session cookie name', [
            'severity' => Severity::INFO,
            'directives' => ['session.name'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-200',
            'description' => 'PHPSESSID identifies the backend as PHP.',
            'recommendation' => 'Choose an application-specific session.name.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.name');
            if ($setting->text() === 'PHPSESSID') {
                yield new Hit('session.name is PHPSESSID', [$setting]);
            }
        });

        Registry::rule('SESS-013', 'Persistent session cookie', [
            'severity' => Severity::INFO,
            'directives' => ['session.cookie_lifetime'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-539',
            'description' => 'A non-zero cookie_lifetime stores the session cookie on disk in the browser.',
            'recommendation' => 'Use session.cookie_lifetime = 0 and handle "remember me" separately.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.cookie_lifetime');
            if ($setting->asInt() > 0) {
                yield new Hit("{$setting->describe()} seconds", [$setting]);
            }
        });

        Registry::rule('SESS-014', 'Session cookie shared with other hosts', [
            'severity' => Severity::INFO,
            'directives' => ['session.cookie_domain'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-565',
            'description' => 'A cookie_domain makes the session cookie visible to every subdomain, so one compromised '
                . 'subdomain can read or overwrite it.',
            'recommendation' => 'Leave session.cookie_domain empty unless sessions must span subdomains.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('session.cookie_domain');
            if ($setting->text() !== '') {
                yield new Hit($setting->describe(), [$setting]);
            }
        });
    }
}

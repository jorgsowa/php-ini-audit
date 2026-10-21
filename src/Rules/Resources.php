<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Severity;

/** Resource limits that bound denial-of-service impact. */
final class Resources
{
    public const GIB = 1073741824;

    public static function register(): void
    {
        Registry::rule('RES-001', 'Unlimited or very large memory_limit', [
            'severity' => Severity::MEDIUM,
            'directives' => ['memory_limit'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-770',
            'description' => 'memory_limit = -1 lets one request exhaust server memory.',
            'recommendation' => 'Set memory_limit to what the application needs (typically 128M-512M).',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('memory_limit');
            $size = $setting->asBytes();
            if ($size !== null && $size < 0) {
                if (Vulnerabilities::exposedTo('CVE-2026-109618', $ctx->phpVersion)) {
                    yield new Hit('memory_limit is unlimited (-1), the interim mitigation for CVE-2026-109618; '
                        . 'restore a limit after upgrading', [$setting], Severity::INFO);
                } else {
                    yield new Hit('memory_limit is unlimited (-1)', [$setting]);
                }
            } elseif ($size !== null && $size > self::GIB) {
                yield new Hit("{$setting->describe()} (> 1G)", [$setting], Severity::LOW);
            }
        });

        Registry::rule('RES-002', 'Unlimited or long max_execution_time', [
            'severity' => Severity::MEDIUM,
            'directives' => ['max_execution_time'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-400',
            'description' => 'max_execution_time = 0 lets slow or stuck requests occupy workers forever.',
            'recommendation' => 'Use 30-60 seconds for web requests (and request_terminate_timeout in FPM).',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('max_execution_time');
            $seconds = $setting->asInt();
            if ($seconds <= 0) {
                yield new Hit('max_execution_time is unlimited', [$setting]);
            } elseif ($seconds > 300) {
                yield new Hit("{$setting->describe()} seconds", [$setting], Severity::LOW);
            }
        });

        Registry::rule('RES-003', 'Unlimited or very large POST bodies', [
            'severity' => Severity::MEDIUM,
            'directives' => ['post_max_size'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-770',
            'description' => 'post_max_size = 0 removes the request body limit.',
            'recommendation' => 'Set post_max_size slightly above the largest legitimate upload.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('post_max_size');
            $size = $setting->asBytes();
            if ($size === 0) {
                yield new Hit('post_max_size is unlimited (0)', [$setting]);
            } elseif ($size !== null && $size > self::GIB) {
                yield new Hit("{$setting->describe()} (> 1G)", [$setting], Severity::LOW);
            }
        });

        Registry::rule('RES-004', 'Very large uploads accepted', [
            'severity' => Severity::LOW,
            'directives' => ['upload_max_filesize', 'post_max_size'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-770',
            'description' => 'Large upload limits let clients fill the temp directory and disk.',
            'recommendation' => 'Keep upload_max_filesize to the real requirement and below post_max_size.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('upload_max_filesize');
            $size = $setting->asBytes();
            if ($size !== null && $size > self::GIB) {
                yield new Hit("{$setting->describe()} (> 1G)", [$setting]);
            }
            $post = $ctx->get('post_max_size')->asBytes();
            if ($size !== null && $size !== 0 && $post !== null && $post > 0 && $size > $post) {
                yield new Hit(
                    'upload_max_filesize exceeds post_max_size; larger uploads fail silently',
                    [$setting, $ctx->get('post_max_size')],
                    Severity::LOW
                );
            }
        });

        Registry::rule('RES-005', 'max_input_vars raised or disabled', [
            'severity' => Severity::LOW,
            'directives' => ['max_input_vars'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-407',
            'description' => 'max_input_vars caps request variables and protects against hash-collision DoS '
                . '(CVE-2011-4885).',
            'recommendation' => 'Keep max_input_vars at 1000-5000.',
            'references' => ['https://nvd.nist.gov/vuln/detail/CVE-2011-4885'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('max_input_vars');
            $count = $setting->asInt();
            if ($count <= 0 || $count > 10000) {
                yield new Hit($setting->describe(), [$setting]);
            }
        });

        Registry::rule('RES-006', 'Deep input nesting allowed', [
            'severity' => Severity::LOW,
            'directives' => ['max_input_nesting_level'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-674',
            'description' => 'Deeply nested request arrays cost CPU and memory to parse.',
            'recommendation' => 'Keep max_input_nesting_level at 64.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('max_input_nesting_level');
            if ($setting->asInt() > 256) {
                yield new Hit($setting->describe(), [$setting]);
            }
        });

        Registry::rule('RES-007', 'Many files per request accepted', [
            'severity' => Severity::LOW,
            'directives' => ['max_file_uploads'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-770',
            'description' => 'Each uploaded file costs a temp file and file descriptor.',
            'recommendation' => "Keep max_file_uploads at 20 or the application's real need.",
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('max_file_uploads');
            if ($setting->asInt() > 100) {
                yield new Hit($setting->describe(), [$setting]);
            }
        });

        Registry::rule('RES-008', 'Regular expression limits raised', [
            'severity' => Severity::LOW,
            'directives' => ['pcre.backtrack_limit', 'pcre.recursion_limit'],
            'cwe' => 'CWE-1333',
            'description' => 'Higher PCRE limits make catastrophic backtracking (ReDoS) and stack exhaustion '
                . 'crashes easier.',
            'recommendation' => 'Keep pcre.backtrack_limit = 1000000 and pcre.recursion_limit = 100000.',
        ], static function (Context $ctx): iterable {
            foreach (['pcre.backtrack_limit' => 1000000, 'pcre.recursion_limit' => 100000] as $name => $limit) {
                $setting = $ctx->get($name);
                if ($setting->asInt() > $limit) {
                    yield new Hit("{$setting->describe()} (default $limit)", [$setting]);
                }
            }
        });

        Registry::rule('RES-009', 'unserialize() nesting depth unlimited', [
            'severity' => Severity::LOW,
            'directives' => ['unserialize_max_depth'],
            'cwe' => 'CWE-674',
            'description' => 'unserialize_max_depth = 0 lets deeply nested payloads exhaust the stack.',
            'recommendation' => 'Keep unserialize_max_depth = 4096 or lower.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('unserialize_max_depth');
            if ($setting->asInt() <= 0) {
                yield new Hit('unserialize_max_depth is unlimited', [$setting]);
            }
        });

        Registry::rule('RES-010', 'Socket reads may block indefinitely', [
            'severity' => Severity::LOW,
            'directives' => ['default_socket_timeout'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-400',
            'description' => 'A negative or very long default_socket_timeout lets slow remote peers hold workers.',
            'recommendation' => 'Use 60 seconds or less.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('default_socket_timeout');
            $seconds = $setting->asInt();
            if ($seconds < 0 || $seconds > 300) {
                yield new Hit($setting->describe(), [$setting]);
            }
        });

        Registry::rule('RES-011', 'Unlimited multipart body parts', [
            'severity' => Severity::LOW,
            'directives' => ['max_multipart_body_parts', 'max_input_vars', 'max_file_uploads'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-770',
            'description' => 'max_multipart_body_parts bounds multipart parsing (CVE-2023-0662); when it is -1 the '
                . 'bound is max_input_vars + max_file_uploads, so raising those raises it too.',
            'recommendation' => 'Keep max_input_vars and max_file_uploads modest, or set max_multipart_body_parts.',
            'references' => ['https://nvd.nist.gov/vuln/detail/CVE-2023-0662'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('max_multipart_body_parts');
            $explicit = $setting->asInt();
            if ($explicit > 10000) {
                yield new Hit($setting->describe(), [$setting]);
            } elseif ($explicit < 0) {
                $derived = $ctx->get('max_input_vars')->asInt() + $ctx->get('max_file_uploads')->asInt();
                if ($derived > 10000) {
                    yield new Hit(
                        "effective multipart part limit is $derived",
                        [$setting, $ctx->get('max_input_vars'), $ctx->get('max_file_uploads')]
                    );
                }
            }
        });
    }
}

<?php

namespace PhpIniAudit\Rules;

use PhpIniAudit\Confidence;
use PhpIniAudit\Severity;
use PhpIniAudit\Values;

/** Error handling and information disclosure. */
final class Disclosure
{
    public static function register(): void
    {
        Registry::rule('ERR-001', 'Errors displayed to visitors', [
            'severity' => Severity::MEDIUM,
            'dev_severity' => Severity::INFO,
            'directives' => ['display_errors', 'html_errors'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-209',
            'description' => 'display_errors prints warnings and stack traces into responses, disclosing paths, '
                . "queries, and sometimes credentials. PHP's built-in default is On when no php.ini is loaded.",
            'recommendation' => 'Set display_errors = Off and log_errors = On in production.',
            'references' => ['https://www.php.net/manual/en/errorfunc.configuration.php#ini.display-errors'],
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('display_errors');
            $text = strtolower($setting->text());
            if ($text === 'stderr') {
                return;
            }
            if ($text === 'stdout' || $setting->asBool()) {
                yield new Hit('display_errors is On', [$setting]);
            }
        });

        Registry::rule('ERR-002', 'Start-up errors displayed', [
            'severity' => Severity::LOW,
            'dev_severity' => Severity::INFO,
            'directives' => ['display_startup_errors'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-209',
            'description' => "display_startup_errors shows errors raised during PHP's start-up sequence in the output.",
            'recommendation' => 'Set display_startup_errors = Off in production.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('display_startup_errors');
            if ($setting->asBool()) {
                yield new Hit('display_startup_errors is On', [$setting]);
            }
        });

        Registry::rule('ERR-003', 'Errors are not logged', [
            'severity' => Severity::LOW,
            'directives' => ['log_errors'],
            'cwe' => 'CWE-778',
            'description' => 'Without log_errors, probing and exploitation attempts that trigger warnings leave no '
                . 'trace.',
            'recommendation' => 'Set log_errors = On and configure error_log.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('log_errors');
            if (!$setting->asBool()) {
                yield new Hit('log_errors is Off', [$setting]);
            }
        });

        Registry::rule('ERR-004', 'PHP version disclosed in HTTP headers', [
            'severity' => Severity::LOW,
            'directives' => ['expose_php'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-200',
            'description' => 'expose_php adds an X-Powered-By header with the exact PHP version, which helps '
                . 'attackers pick exploits.',
            'recommendation' => 'Set expose_php = Off.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('expose_php');
            if ($setting->asBool()) {
                yield new Hit('expose_php is On', [$setting]);
            }
        });

        Registry::rule('ERR-005', 'Function arguments included in stack traces', [
            'severity' => Severity::LOW,
            'directives' => ['zend.exception_ignore_args'],
            'production_only' => true,
            'cwe' => 'CWE-532',
            'description' => 'With zend.exception_ignore_args = Off, exception traces carry argument values such as '
                . 'passwords and tokens into logs and error pages.',
            'recommendation' => 'Set zend.exception_ignore_args = On in production.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('zend.exception_ignore_args');
            if (!$setting->asBool()) {
                yield new Hit('zend.exception_ignore_args is Off', [$setting]);
            }
        });

        Registry::rule('ERR-006', 'Error reporting disabled', [
            'severity' => Severity::LOW,
            'directives' => ['error_reporting'],
            'cwe' => 'CWE-778',
            'description' => 'error_reporting = 0 suppresses logging of every error, hiding attacks and bugs alike.',
            'recommendation' => 'Use error_reporting = E_ALL and control visibility with display_errors.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('error_reporting');
            $level = Values::evalErrorReporting($setting->value);
            if ($level === 0) {
                yield new Hit('error_reporting evaluates to 0', [$setting]);
            }
        });

        Registry::rule('ERR-007', 'Script path added to outgoing mail headers', [
            'severity' => Severity::LOW,
            'directives' => ['mail.add_x_header'],
            'cwe' => 'CWE-200',
            'description' => "mail.add_x_header adds X-PHP-Originating-Script with the script's UID and file name to "
                . 'every message.',
            'recommendation' => 'Set mail.add_x_header = Off.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('mail.add_x_header');
            if ($setting->asBool()) {
                yield new Hit('mail.add_x_header is On', [$setting]);
            }
        });

        Registry::rule('ERR-008', 'Environment variables copied into $_ENV', [
            'severity' => Severity::LOW,
            'directives' => ['variables_order'],
            'sapis' => Base::WEB_SAPIS,
            'cwe' => 'CWE-526',
            'description' => "An 'E' in variables_order copies the process environment, often holding secrets, into "
                . '$_ENV where debug dumps and phpinfo() reveal it.',
            'recommendation' => 'Use variables_order = "GPCS" and read configuration with getenv().',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('variables_order');
            if (strpos(strtoupper($setting->text()), 'E') !== false) {
                yield new Hit("{$setting->describe()} populates \$_ENV", [$setting], null, Confidence::MEDIUM);
            }
        });

        Registry::rule('ERR-009', 'Error log created world-writable', [
            'severity' => Severity::LOW,
            'directives' => ['error_log_mode'],
            'cwe' => 'CWE-732',
            'description' => 'error_log_mode controls the permissions of a newly created error log; a world-writable '
                . 'log can be forged or used for log poisoning.',
            'recommendation' => 'Use error_log_mode = 0640 or stricter.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('error_log_mode');
            $mode = Values::parseOctal($setting->value);
            if ($mode !== null && ($mode & 0002)) {
                yield new Hit("{$setting->describe()} grants write access to others", [$setting]);
            }
        });

        Registry::rule('ERR-010', 'phpinfo() callable', [
            'severity' => Severity::INFO,
            'directives' => ['disable_functions'],
            'sapis' => Base::WEB_SAPIS,
            'production_only' => true,
            'cwe' => 'CWE-200',
            'description' => 'A forgotten phpinfo() page reveals configuration, paths, environment variables and '
                . 'cookies.',
            'recommendation' => 'Add phpinfo to disable_functions in production.',
        ], static function (Context $ctx): iterable {
            if (!isset(Execution::disabledFunctions($ctx)['phpinfo'])) {
                yield new Hit('phpinfo() is not disabled', [$ctx->get('disable_functions')], null, Confidence::LOW);
            }
        });

        Registry::rule('ERR-011', 'Long string arguments kept in stack traces', [
            'severity' => Severity::INFO,
            'directives' => ['zend.exception_string_param_max_len'],
            'cwe' => 'CWE-532',
            'description' => 'Raising zend.exception_string_param_max_len stores more of each string argument in '
                . 'traces.',
            'recommendation' => 'Keep the default (15) or lower.',
        ], static function (Context $ctx): iterable {
            $setting = $ctx->get('zend.exception_string_param_max_len');
            if ($setting->asInt() > 15) {
                yield new Hit($setting->describe(), [$setting]);
            }
        });
    }
}

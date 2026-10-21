<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Confidence;
use PhpIniAudit\Finding;
use PhpIniAudit\Rules\Registry;
use PhpIniAudit\Severity;
use PHPUnit\Framework\TestCase;

final class RulesTest extends TestCase
{
    private const HARDENED = "expose_php = Off\ndisplay_errors = Off\ndisplay_startup_errors = Off\nlog_errors = On\n"
        . "zend.exception_ignore_args = On\nzend.assertions = -1\nvariables_order = GPCS\nregister_argc_argv = Off\n"
        . "enable_dl = Off\nallow_url_fopen = Off\nfile_uploads = Off\nopen_basedir = /srv/app/\n"
        . 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,putenv,mail,'
        . "mb_send_mail,imap_mail,error_log,phpinfo\ninclude_path = /usr/share/php\nuser_ini.filename =\n"
        . "session.save_path = /var/lib/php/sessions\nsession.use_strict_mode = 1\nsession.cookie_httponly = 1\n"
        . "session.cookie_secure = 1\nsession.cookie_samesite = Lax\nsession.name = APP\n"
        . "session.upload_progress.enabled = Off\ncgi.fix_pathinfo = 0\nopcache.restrict_api = /srv/app/admin/\n"
        . "opcache.validate_permission = 1\nopcache.validate_root = 1\n";

    // Registry

    public function testEveryRuleIsDocumented(): void
    {
        foreach (Registry::all() as $rule) {
            $this->assertTrue($rule->description !== '' && $rule->recommendation !== '', $rule->id);
            $this->assertContains($rule->scope, ['config', 'file', 'pool'], $rule->id);
            $this->assertMatchesRegularExpression('/^([A-Z]+-\d{3}|CVE-\d{4}-\d{4,})$/', $rule->id);
        }
    }

    // Defaults

    public function testEmptyConfigReportsInsecureBuiltinDefaults(): void
    {
        $result = Helpers::auditIni('');
        $ids = Helpers::ruleIds($result);
        foreach (['ERR-001', 'EXEC-011', 'EXEC-005', 'FS-001', 'SESS-001', 'SESS-005', 'ERR-004'] as $expected) {
            $this->assertContains($expected, $ids);
        }
        $display = Helpers::findingsFor($result, 'ERR-001')[0];
        $this->assertTrue($display->fromDefault);
        $this->assertNull($display->location);
    }

    public function testHardenedConfigIsQuiet(): void
    {
        $result = Helpers::auditIni(self::HARDENED);
        $loud = array_filter($result->findings, static function (Finding $f): bool {
            return $f->severity >= Severity::LOW;
        });
        $this->assertSame([], array_values(array_map(static function (Finding $f): string {
            return $f->ruleId;
        }, $loud)));
    }

    public function testReportIsNotBinary(): void
    {
        $result = Helpers::auditIni("allow_url_include = On\ndisplay_errors = On\n");
        $severities = array_unique(array_map(static function (Finding $f): int {
            return $f->severity;
        }, $result->findings));
        $this->assertGreaterThanOrEqual(3, count($severities));
        $this->assertGreaterThan(10, count($result->findings));
    }

    // Execution rules

    public function testAllowUrlIncludeDependsOnFopen(): void
    {
        $on = Helpers::findingsFor(Helpers::auditIni("allow_url_include = On\n"), 'EXEC-001')[0];
        $this->assertSame(Severity::CRITICAL, $on->severity);
        $off = Helpers::findingsFor(Helpers::auditIni("allow_url_include = On\nallow_url_fopen = Off\n"), 'EXEC-001')[0];
        $this->assertSame(Severity::HIGH, $off->severity);
    }

    public function testPrependWrappers(): void
    {
        $result = Helpers::auditIni("auto_prepend_file = php://input\n");
        $this->assertSame(Severity::CRITICAL, Helpers::findingsFor($result, 'EXEC-003')[0]->severity);
        $this->assertSame([], Helpers::findingsFor($result, 'EXEC-004'));
    }

    public function testPartialDisableFunctions(): void
    {
        $finding = Helpers::findingsFor(Helpers::auditIni("disable_functions = exec,system\n"), 'EXEC-005')[0];
        $this->assertStringContainsString('proc_open', $finding->message);
        $this->assertStringNotContainsString('system,', $finding->message);
    }

    public function testLdPreloadBypassOnlyWhenExecFamilyDisabled(): void
    {
        $sandboxed = "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec\n";
        $this->assertContains('EXEC-006', Helpers::ruleIds(Helpers::auditIni($sandboxed)));
        $this->assertNotContains('EXEC-006', Helpers::ruleIds(Helpers::auditIni("disable_functions = exec\n")));
    }

    public function testSendmailFlags(): void
    {
        $result = Helpers::auditIni("sendmail_path = \"/usr/sbin/sendmail -t -i -X /var/www/log.php\"\n");
        $this->assertStringContainsString('-X', Helpers::findingsFor($result, 'EXEC-013')[0]->message);
    }

    // Scope

    public function testWebRulesSkipCli(): void
    {
        $result = Helpers::auditIni("display_errors = On\nmemory_limit = -1\n", [], ['sapi' => 'cli']);
        $this->assertNotContains('ERR-001', Helpers::ruleIds($result));
        $this->assertNotContains('RES-001', Helpers::ruleIds($result));
    }

    public function testDevelopmentProfileDowngrades(): void
    {
        $result = Helpers::auditIni("display_errors = On\n", [], ['profile' => 'development']);
        $this->assertSame(Severity::INFO, Helpers::findingsFor($result, 'ERR-001')[0]->severity);
        $this->assertNotContains('EXEC-014', Helpers::ruleIds($result));
    }

    public function testUnresolvedValuesLowerConfidence(): void
    {
        $result = Helpers::auditIni("allow_url_include = 1\${ALLOW}\n");
        $finding = Helpers::findingsFor($result, 'EXEC-001')[0];
        $this->assertSame(Confidence::LOW, $finding->confidence);
        $this->assertContains('CFG-007', Helpers::ruleIds($result));
    }

    public function testMinSeverityAndSelection(): void
    {
        $result = Helpers::auditIni('', [], ['minSeverity' => Severity::MEDIUM, 'only' => ['SESS']]);
        $this->assertNotEmpty($result->findings);
        foreach ($result->findings as $f) {
            $this->assertTrue(strpos($f->ruleId, 'SESS-') === 0 && $f->severity >= Severity::MEDIUM, $f->ruleId);
        }
    }

    // Session rules

    public function testUnquotedSamesiteNone(): void
    {
        $finding = Helpers::findingsFor(Helpers::auditIni("session.cookie_samesite = None\n"), 'SESS-007')[0];
        $this->assertStringContainsString('unquoted', $finding->message);
    }

    public function testSamesiteNoneWithoutSecure(): void
    {
        $finding = Helpers::findingsFor(Helpers::auditIni("session.cookie_samesite = \"None\"\n"), 'SESS-007')[0];
        $this->assertSame(Severity::MEDIUM, $finding->severity);
    }

    public function testDirectivesMissingFromOldVersions(): void
    {
        $old = Helpers::auditIni('', [], ['phpVersion' => [7, 2, 34]]);
        $this->assertEmpty(Helpers::findingsFor($old, 'SESS-007'));
        $this->assertEmpty(Helpers::findingsFor($old, 'ERR-005'));
        $current = Helpers::auditIni('', [], ['phpVersion' => [7, 4, 33]]);
        $this->assertNotEmpty(Helpers::findingsFor($current, 'SESS-007'));
        $this->assertNotEmpty(Helpers::findingsFor($current, 'ERR-005'));
    }

    public function testSidEntropy(): void
    {
        $weak = Helpers::findingsFor(
            Helpers::auditIni("session.sid_length = 22\nsession.sid_bits_per_character = 4\n"),
            'SESS-008'
        );
        $this->assertSame(Severity::LOW, $weak[0]->severity);
    }

    public function testSessionFileMode(): void
    {
        $this->assertContains('SESS-010', Helpers::ruleIds(Helpers::auditIni("session.save_path = \"N;0666;/var/lib/php\"\n")));
    }

    // Filesystem rules

    public function testOpenBasedirEntries(): void
    {
        $result = Helpers::auditIni("open_basedir = /var/www:.:/\n");
        $this->assertStringContainsString('/var/www', Helpers::findingsFor($result, 'FS-003')[0]->message);
        $this->assertStringContainsString('.', Helpers::findingsFor($result, 'FS-004')[0]->message);
        $this->assertContains('FS-002', Helpers::ruleIds($result));
    }

    // Hygiene rules

    public function testTypoOfSecurityDirective(): void
    {
        $finding = Helpers::findingsFor(Helpers::auditIni("expose_phpp = Off\n"), 'CFG-003')[0];
        $this->assertStringContainsString('expose_php', $finding->message);
        $this->assertSame(Severity::MEDIUM, $finding->severity);
    }

    public function testCaseSensitiveNames(): void
    {
        $this->assertContains('CFG-003', Helpers::ruleIds(Helpers::auditIni("Display_Errors = Off\n")));
    }

    public function testObsoleteRegisterGlobals(): void
    {
        $unknown = Helpers::findingsFor(Helpers::auditIni("register_globals = On\n"), 'CFG-002')[0];
        $this->assertSame(Severity::HIGH, $unknown->severity);
        $modern = Helpers::findingsFor(Helpers::auditIni("register_globals = On\n", [], ['phpVersion' => [8, 2]]), 'CFG-002')[0];
        $this->assertSame(Severity::INFO, $modern->severity);
        $legacy = Helpers::findingsFor(Helpers::auditIni("register_globals = On\n", [], ['phpVersion' => [5, 3]]), 'CFG-002')[0];
        $this->assertSame(Severity::CRITICAL, $legacy->severity);
    }

    public function testScanDirOverrideIsReported(): void
    {
        $result = Helpers::auditIni("display_errors = On\n", ['conf.d/99-x.ini' => "display_errors = Off\n"]);
        $this->assertNotContains('ERR-001', Helpers::ruleIds($result));
        $this->assertContains('CFG-004', Helpers::ruleIds($result));
    }

    // Extension rules

    public function testXdebugConnectBack(): void
    {
        $result = Helpers::auditIni("zend_extension = xdebug.so\nxdebug.mode = debug\nxdebug.discover_client_host = 1\n");
        $this->assertSame(Severity::CRITICAL, Helpers::findingsFor($result, 'EXT-001')[0]->severity);
        $this->assertSame(Severity::HIGH, Helpers::findingsFor($result, 'EXT-002')[0]->severity);
    }

    public function testMultibyteCharset(): void
    {
        $this->assertSame(Severity::MEDIUM, Helpers::findingsFor(Helpers::auditIni("default_charset = SJIS\n"), 'ENC-001')[0]->severity);
    }
}

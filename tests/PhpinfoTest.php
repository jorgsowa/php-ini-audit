<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\AuditResult;
use PhpIniAudit\Finding;
use PhpIniAudit\Options;
use PhpIniAudit\Phpinfo;
use PhpIniAudit\PhpinfoDump;
use PHPUnit\Framework\TestCase;

final class PhpinfoTest extends TestCase
{
    public const CLI_OUTPUT = <<<'TEXT'
phpinfo()
PHP Version => 8.2.7-1~deb12u1

System => Linux web 6.1.0 x86_64
Server API => FPM/FastCGI
Loaded Configuration File => /etc/php/8.2/fpm/php.ini
Additional .ini files parsed => /etc/php/8.2/fpm/conf.d/10-opcache.ini,
/etc/php/8.2/fpm/conf.d/20-xdebug.ini

Core

Directive => Local Value => Master Value
allow_url_include => On => On
display_errors => STDOUT => STDOUT
open_basedir => no value => no value

session

Directive => Local Value => Master Value
session.use_strict_mode => Off => Off

xdebug

Directive => Local Value => Master Value
xdebug.mode => debug => debug
xdebug.discover_client_host => On => On

TEXT;

    public const HTML_OUTPUT = <<<'TEXT'
<!DOCTYPE html><html><body><div class="center">
<table><tr class="h"><td><h1 class="p">PHP Version 8.3.12</h1></td></tr></table>
<table>
<tr><td class="e">System </td><td class="v">Windows NT WEB 10.0 build 20348 (Windows Server 2022) AMD64 </td></tr>
<tr><td class="e">Server API </td><td class="v">CGI/FastCGI </td></tr>
<tr><td class="e">Loaded Configuration File </td><td class="v">(none) </td></tr>
</table>
<h2><a name="module_core">Core</a></h2>
<table>
<tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">error_log</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">open_basedir</td><td class="v">C:\inetpub &amp; data</td><td class="v"><i>no value</i></td></tr>
</table>
<h2><a name="module_zend+opcache">Zend OPcache</a></h2>
<table>
<tr><td class="e">opcache.restrict_api</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</table>
</div></body></html>

TEXT;

    // Selecting the rendered page in a browser and copying it yields tab-separated cells.
    public const COPIED_OUTPUT = "PHP Version 8.3.12\n\nServer API\tApache 2.0 Handler\n\nCore\n\n"
        . "Directive\tLocal Value\tMaster Value\nexpose_php\tOn\tOn\nmemory_limit\t-1\t128M\n";

    /** @return list<string> */
    private static function ruleIds(AuditResult $result): array
    {
        return Helpers::ruleIds($result);
    }

    /** @return list<string> */
    private static function modules(PhpinfoDump $info): array
    {
        $modules = array_values(array_unique(array_column($info->modules, 0)));
        sort($modules);
        return $modules;
    }

    // Parse

    public function testCliOutput(): void
    {
        $info = Phpinfo::parse(self::CLI_OUTPUT);
        $target = Phpinfo::buildTarget($info, new Options());
        $this->assertSame('fpm', $target->sapi);
        $this->assertSame([8, 2, 7], $target->phpVersion);
        $this->assertTrue($target->versionBackports);
        $this->assertSame(['/etc/php/8.2/fpm/php.ini', '/etc/php/8.2/fpm/conf.d/10-opcache.ini',
            '/etc/php/8.2/fpm/conf.d/20-xdebug.ini'], $target->files);
        $this->assertSame('1', $target->config->get('display_errors')->value);
        $this->assertSame('', $target->config->get('open_basedir')->value);
        $this->assertSame(13, $target->config->get('allow_url_include')->location()->line);
        $this->assertSame(['core', 'session', 'xdebug'], self::modules($info));
    }

    public function testHtmlPage(): void
    {
        $info = Phpinfo::parse(self::HTML_OUTPUT);
        $target = Phpinfo::buildTarget($info, new Options());
        $this->assertSame([8, 3, 12], $target->phpVersion);
        $this->assertSame('cgi', $target->sapi);
        $this->assertSame('windows', $target->platform);
        $this->assertSame([], $target->files);
        $this->assertNotNull($target->defaultsReason);
        $this->assertSame('C:\\inetpub & data', $target->config->get('open_basedir')->value);
        $this->assertSame('', $target->config->get('error_log')->value);
        $this->assertSame(['core', 'opcache'], self::modules($info));
    }

    public function testCopiedPage(): void
    {
        $target = Phpinfo::buildTarget(Phpinfo::parse(self::COPIED_OUTPUT), new Options());
        $this->assertSame('apache2', $target->sapi);
        $this->assertSame([8, 3, 12], $target->phpVersion);
        $this->assertSame('-1', $target->config->get('memory_limit')->value);
    }

    public function testRejectsOtherText(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Phpinfo::parse('<html><body><p>Hello</p></body></html>');
    }

    // Audit

    public function testFindings(): void
    {
        $result = Phpinfo::audit(self::CLI_OUTPUT);
        $ids = self::ruleIds($result);
        $expected = ['EXEC-001', 'ERR-001', 'SESS-001', 'EXT-001', 'EXT-002', 'FS-001'];
        $this->assertSame([], array_values(array_diff($expected, $ids)), implode(', ', $ids));
        $include = Helpers::findingsFor($result, 'EXEC-001')[0];
        $this->assertSame('phpinfo():13', (string) $include->location);
        $this->assertFalse($result->pathChecks);
    }

    public function testDirectivesMissingFromPhpinfoAreNotReported(): void
    {
        $ids = self::ruleIds(Phpinfo::audit(self::COPIED_OUTPUT));
        $this->assertContains('RES-001', $ids);
        $this->assertContains('ERR-004', $ids);
        // No session module in the dump, so session defaults must not produce findings.
        $this->assertSame([], array_values(array_filter($ids, static function (string $id): bool {
            return strpos($id, 'SESS-') === 0;
        })));
    }

    public function testNoPhpIni(): void
    {
        $this->assertContains('CFG-006', self::ruleIds(Phpinfo::audit(self::HTML_OUTPUT)));
    }

    public function testOptionsOverride(): void
    {
        $result = Phpinfo::audit(self::CLI_OUTPUT, Helpers::options(['sapi' => 'cli', 'phpVersion' => [8, 3, 0]]));
        $this->assertSame('cli', $result->targets[0]->sapi);
        $this->assertSame('--php-version', $result->targets[0]->versionSource);
        $this->assertNotContains('FS-001', self::ruleIds($result));
    }

    // CLI

    public function testPhpinfoFile(): void
    {
        $tmp = Helpers::tempDir();
        try {
            file_put_contents("$tmp/info.html", self::HTML_OUTPUT);
            [$code, $out] = Helpers::runCli('--phpinfo', "$tmp/info.html", '--format', 'json', '--fail-on', 'medium');
            $this->assertSame(1, $code);
            $this->assertSame('phpinfo()', json_decode($out, true, 512, JSON_THROW_ON_ERROR)['targets'][0]['name']);
        } finally {
            Helpers::removeTree($tmp);
        }
    }

    public function testNotPhpinfo(): void
    {
        $tmp = Helpers::tempDir();
        try {
            file_put_contents("$tmp/php.ini", "display_errors = On\n");
            [$code, , $err] = Helpers::runCli('--phpinfo', "$tmp/php.ini");
        } finally {
            Helpers::removeTree($tmp);
        }
        $this->assertSame(2, $code);
        $this->assertStringContainsString('no phpinfo()', $err);
    }
}

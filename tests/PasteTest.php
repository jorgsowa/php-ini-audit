<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Paste;
use PHPUnit\Framework\TestCase;

final class PasteTest extends TestCase
{
    private static function fixture(string $path): string
    {
        return (string) file_get_contents(Helpers::FIXTURES . '/' . $path);
    }

    /** @return iterable<string, array{string, string}> */
    public function kindProvider(): iterable
    {
        $cases = [
            'phpinfo' => [PhpinfoTest::CLI_OUTPUT, PhpinfoTest::HTML_OUTPUT, PhpinfoTest::COPIED_OUTPUT],
            'php.ini' => [self::fixture('debian/etc/php/8.2/fpm/php.ini'), self::fixture('windows-xampp/php.ini'),
                "display_errors = On\n"],
            'fpm' => [self::fixture('debian/etc/php/8.2/fpm/pool.d/www.conf'),
                self::fixture('docker/usr/local/etc/php-fpm.d/zz-docker.conf')],
            'htaccess' => [self::fixture('webroot/uploads/.htaccess'), "php_flag display_errors on\n"],
        ];
        foreach ($cases as $kind => $texts) {
            foreach ($texts as $i => $text) {
                yield "$kind #$i" => [$kind, $text];
            }
        }
    }

    /** @dataProvider kindProvider */
    public function testKinds(string $kind, string $text): void
    {
        $this->assertSame($kind, Paste::detect($text));
    }

    public function testBlankLinesAreLinear(): void
    {
        $start = microtime(true);
        $this->assertSame('php.ini', Paste::detect(str_repeat(" \n", 50000) . 'x'));
        $this->assertLessThan(1, microtime(true) - $start);
    }

    public function testPhpIni(): void
    {
        [$kind, $result] = Paste::audit("allow_url_include = On\n", null, Helpers::options(['phpVersion' => [8, 1, 0]]));
        $this->assertSame('php.ini', $kind);
        $include = Helpers::findingsFor($result, 'EXEC-001')[0];
        $this->assertSame('php.ini:1', (string) $include->location);
        $this->assertContains('VULN-001', Helpers::ruleIds($result));
        $this->assertFalse($result->pathChecks);
    }

    public function testPool(): void
    {
        [$kind, $result] = Paste::audit(self::fixture('debian/etc/php/8.2/fpm/pool.d/www.conf'));
        $this->assertSame('fpm', $kind);
        $ids = Helpers::ruleIds($result);
        $this->assertContains('FPM-001', $ids);
        $this->assertContains('FPM-004', $ids);
    }

    public function testHtaccess(): void
    {
        [$kind, $result] = Paste::audit(self::fixture('webroot/uploads/.htaccess'));
        $this->assertSame('htaccess', $kind);
        $this->assertContains('HTA-001', Helpers::ruleIds($result));
    }

    public function testUserIniMustBeChosen(): void
    {
        $text = self::fixture('webroot/.user.ini');
        $this->assertNotContains('CFG-005', Helpers::ruleIds(Paste::audit($text)[1]));
        [$kind, $result] = Paste::audit($text, 'user.ini');
        $this->assertSame('user.ini', $kind);
        $this->assertContains('CFG-005', Helpers::ruleIds($result));
    }

    public function testPhpinfo(): void
    {
        [$kind, $result] = Paste::audit(PhpinfoTest::CLI_OUTPUT);
        $this->assertSame('phpinfo', $kind);
        $this->assertSame('phpinfo()', $result->targets[0]->name());
    }

    /** @return list<array{string, ?string}> */
    public function rejectedProvider(): array
    {
        return [['', null], ["just some words\n", null], ["display_errors = On\n", 'phpinfo']];
    }

    /** @dataProvider rejectedProvider */
    public function testRejectsEmptyInput(string $text, ?string $kind): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Paste::audit($text, $kind);
    }

    public function testParseVersion(): void
    {
        $this->assertSame([8, 3, 12], Paste::parseVersion(' 8.3.12 '));
        $this->assertNull(Paste::parseVersion(''));
        $this->expectException(\InvalidArgumentException::class);
        Paste::parseVersion('8');
    }
}

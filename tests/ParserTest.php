<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Directive;
use PhpIniAudit\Parser;
use PhpIniAudit\SourceKind;
use PHPUnit\Framework\TestCase;

final class ParserTest extends TestCase
{
    public function testBareBooleansAreNormalised(): void
    {
        $this->assertSame('1', Parser::scanValue(' On ; comment')[0]);
        $this->assertSame('', Parser::scanValue(' None')[0]);
        $this->assertSame('None', Parser::scanValue(' "None"')[0]);
    }

    public function testQuotesAndComments(): void
    {
        $this->assertSame('N;0700;/tmp', Parser::scanValue(' "N;0700;/tmp" ; trailing')[0]);
        $this->assertSame('N', Parser::scanValue(' N;0700;/tmp')[0]);
        $this->assertSame('a;b', Parser::scanValue(" 'a;b'")[0]);
        $this->assertSame('C:\\php\\ext', Parser::scanValue(' "C:\\\\php\\\\ext"')[0]);
    }

    public function testEnvReferenceIsFlagged(): void
    {
        [$value, $unresolved] = Parser::scanValue(' ${MEMORY}');
        $this->assertSame('${MEMORY}', $value);
        $this->assertTrue($unresolved);
    }

    public function testUnterminatedQuote(): void
    {
        $this->assertTrue(Parser::scanValue(' "open')[2]);
    }

    public function testIniDirectivesSectionsAndIssues(): void
    {
        $text = "[PHP]\n"
            . "display_errors = Off\n"
            . "# hash comment\n"
            . "garbage line\n"
            . "include_path = \".:/a\n:/b\"\n"
            . "[PATH=/var/www/x]\n"
            . "allow_url_fopen = On\n";
        $parsed = Parser::parseIni($text, '/etc/php.ini', SourceKind::PHP_INI);
        $this->assertSame(['display_errors', 'include_path', 'allow_url_fopen'], self::names($parsed->directives));
        $this->assertSame(".:/a\n:/b", $parsed->directives[1]->value);
        $this->assertCount(2, $parsed->issues);
        $this->assertSame(['display_errors', 'include_path'], self::names($parsed->baseDirectives()));
        $this->assertSame('PATH=/var/www/x', $parsed->conditionalSections[0][0]);
        $this->assertSame(2, $parsed->directives[0]->location->line);
    }

    public function testFpmPools(): void
    {
        $text = "[global]\nerror_log = /var/log/fpm.log\n"
            . "[www]\nlisten = /run/php.sock\n"
            . "php_admin_value[disable_functions] = exec\n"
            . "php_flag[display_errors] = off\n"
            . "env[TOKEN] = abc\n";
        $parsed = Parser::parseFpm($text, '/etc/php-fpm.d/www.conf');
        $this->assertArrayHasKey('error_log', $parsed->globalSettings);
        $pool = $parsed->pools[0];
        $this->assertSame('www', $pool->name);
        $this->assertSame('/run/php.sock', $pool->settings['listen']->value);
        $this->assertSame(
            [['disable_functions', 'exec', true], ['display_errors', '', false]],
            array_map(static function (Directive $d): array {
                return [$d->name, $d->value, $d->admin];
            }, $pool->php)
        );
        $this->assertSame('TOKEN', $pool->env[0]->name);
    }

    public function testHtaccessPhpDirectivesAndHandlers(): void
    {
        $text = "php_flag display_errors on\n"
            . "php_value auto_prepend_file \"/tmp/x.php\"\n"
            . "php_admin_flag engine off\n"
            . "AddHandler application/x-httpd-php .php .png\n"
            . "<FilesMatch \"\\.txt$\">\nSetHandler application/x-httpd-php\n</FilesMatch>\n";
        $parsed = Parser::parseHtaccess($text, '/var/www/.htaccess');
        $this->assertSame(
            [['display_errors', '1'], ['auto_prepend_file', '/tmp/x.php']],
            array_map(static function (Directive $d): array {
                return [$d->name, $d->value];
            }, $parsed->directives)
        );
        $this->assertCount(1, $parsed->issues);
        $this->assertSame(['.php', '.png'], $parsed->handlers[0]->extensions);
        $this->assertSame('\\.txt$', $parsed->handlers[1]->filesPattern);
    }

    /** @param list<Directive> $directives */
    private static function names(array $directives): array
    {
        return array_map(static function (Directive $d): string {
            return $d->name;
        }, $directives);
    }
}

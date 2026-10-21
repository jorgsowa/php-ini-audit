<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Rules\Registry;
use PHPUnit\Framework\TestCase;

final class DocsTest extends TestCase
{
    private const ROOT = __DIR__ . '/..';

    public function testGeneratedRegionsAreCurrent(): void
    {
        require_once self::ROOT . '/scripts/build_docs.php';
        $this->assertSame(0, \main(['--check']), 'run php scripts/build_docs.php');
    }

    public function testEveryRuleIsDocumented(): void
    {
        $page = (string) file_get_contents(self::ROOT . '/docs/rules.html');
        $missing = [];
        foreach (array_keys(Registry::all()) as $ruleId) {
            if (strpos($page, 'id="' . $ruleId . '"') === false) {
                $missing[] = (string) $ruleId;
            }
        }
        $this->assertSame([], $missing);
    }

    public function testInternalRuleLinksResolve(): void
    {
        $registry = Registry::all();
        $pages = glob(self::ROOT . '/docs/*.html') ?: [];
        $this->assertNotEmpty($pages);
        foreach ($pages as $page) {
            preg_match_all('/rules\.html#([A-Z]+-\d{3})/', (string) file_get_contents($page), $matches);
            foreach ($matches[1] as $ruleId) {
                $this->assertArrayHasKey($ruleId, $registry, basename($page) . " links to unknown rule $ruleId");
            }
        }
    }
}

<?php

namespace PhpIniAudit\Tests;

use PhpIniAudit\Values;
use PHPUnit\Framework\TestCase;

final class ValuesTest extends TestCase
{
    public function testBoolFollowsZendIniParseBool(): void
    {
        foreach (['1', 'On', 'yes', 'TRUE', '2', ' 1 '] as $text) {
            $this->assertTrue(Values::toBool($text), $text);
        }
        foreach (['', '0', 'Off', 'no', 'stderr', null, 'abc'] as $text) {
            $this->assertFalse(Values::toBool($text), var_export($text, true));
        }
    }

    public function testQuantities(): void
    {
        $this->assertSame(128 * 1024 ** 2, Values::toBytes('128M'));
        $this->assertSame(2 * 1024 ** 3, Values::toBytes('2g'));
        $this->assertSame(-1, Values::toBytes('-1'));
        $this->assertSame(16, Values::toBytes('0x10'));
        $this->assertNull(Values::toBytes('lots'));
    }

    public function testErrorReportingExpression(): void
    {
        $this->assertSame(32767, Values::evalErrorReporting('E_ALL'));
        $this->assertSame(32767 & ~8192 & ~2048, Values::evalErrorReporting('E_ALL & ~E_DEPRECATED & ~E_STRICT'));
        $this->assertSame(3, Values::evalErrorReporting('(E_ERROR | E_WARNING)'));
        $this->assertSame(0, Values::evalErrorReporting('0'));
        $this->assertNull(Values::evalErrorReporting('E_BOGUS'));
        $this->assertNull(Values::evalErrorReporting("__import__('os')"));
    }

    public function testListSplit(): void
    {
        $this->assertSame(['exec', 'system', 'popen', 'shell_exec'], Values::splitList('exec, system,,popen  shell_exec'));
    }
}

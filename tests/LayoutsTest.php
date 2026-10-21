<?php

namespace PhpIniAudit\Tests;

use PHPUnit\Framework\TestCase;

/** Discovery and version detection over the on-disk layouts of real distributions and bundles, via --root. */
final class LayoutsTest extends TestCase
{
    private static function dpkg(string $package, string $version): string
    {
        return "Package: $package\nStatus: install ok installed\nVersion: $version\n\n";
    }

    private static function apk(string $package, string $version): string
    {
        return "P:$package\nV:$version\nA:x86_64\n\n";
    }

    private static function header(string $version): string
    {
        return "#define PHP_VERSION \"$version\"\n";
    }

    /**
     * name => [files, symlinks {link: target}, expected {target name: [sapi, version, version source, files]}]
     *
     * @return array<string, array{0: array<string, string>, 1: array<string, string>, 2: array<string, array>}>
     */
    private static function layouts(): array
    {
        return [
            'rhel' => [
                [
                    'etc/php.ini' => "expose_php = On\n",
                    'etc/php.d/10-opcache.ini' => "zend_extension=opcache\n",
                    'etc/php.d/20-sodium.ini' => "extension=sodium\n",
                    'etc/php-fpm.conf' => "[global]\ninclude=/etc/php-fpm.d/*.conf\n",
                    'etc/php-fpm.d/www.conf' => "[www]\nlisten = /run/php-fpm/www.sock\n",
                    'usr/include/php/main/php_version.h' => self::header('8.1.27'),
                ],
                [],
                [
                    '/etc/php.ini' => ['unknown', '8.1.27', '/usr/include/php/main/php_version.h',
                        ['/etc/php.ini', '/etc/php.d/10-opcache.ini', '/etc/php.d/20-sodium.ini']],
                    '/etc/php.ini + pool [www] (/etc/php-fpm.d/www.conf)' => ['fpm', '8.1.27', null, null],
                ],
            ],
            'remi' => [
                [
                    'etc/opt/remi/php83/php.ini' => "expose_php = On\n",
                    'etc/opt/remi/php83/php.d/10-opcache.ini' => "zend_extension=opcache\n",
                    'opt/remi/php83/root/usr/include/php/main/php_version.h' => self::header('8.3.4'),
                    'etc/opt/remi/php82/php.ini' => "expose_php = On\n",
                    'opt/remi/php82/root/usr/include/php/main/php_version.h' => self::header('8.2.18'),
                ],
                [],
                [
                    '/etc/opt/remi/php83/php.ini' => ['unknown', '8.3.4',
                        '/opt/remi/php83/root/usr/include/php/main/php_version.h',
                        ['/etc/opt/remi/php83/php.ini', '/etc/opt/remi/php83/php.d/10-opcache.ini']],
                    '/etc/opt/remi/php82/php.ini' => ['unknown', '8.2.18',
                        '/opt/remi/php82/root/usr/include/php/main/php_version.h', ['/etc/opt/remi/php82/php.ini']],
                ],
            ],
            'alpine' => [
                [
                    'etc/php83/php.ini' => "expose_php = On\n",
                    'etc/php83/conf.d/00_opcache.ini' => "zend_extension=opcache\n",
                    'etc/php83/php-fpm.conf' => "[global]\nerror_log = /var/log/php83/error.log\n",
                    'etc/php83/php-fpm.d/www.conf' => "[www]\nlisten = 127.0.0.1:9000\n",
                    'lib/apk/db/installed' => self::apk('musl', '1.2.5-r0') . self::apk('php83', '8.3.12-r0')
                        . self::apk('php83-fpm', '8.3.12-r0'),
                ],
                [],
                [
                    '/etc/php83/php.ini' => ['unknown', '8.3.12', '/lib/apk/db/installed (php83 8.3.12-r0)',
                        ['/etc/php83/php.ini', '/etc/php83/conf.d/00_opcache.ini']],
                    '/etc/php83/php.ini + pool [www] (/etc/php83/php-fpm.d/www.conf)' => ['fpm', '8.3.12', null, null],
                ],
            ],
            'homebrew' => [
                [
                    'opt/homebrew/etc/php/8.3/php.ini' => "expose_php = On\n",
                    'opt/homebrew/etc/php/8.3/conf.d/ext-opcache.ini' => "zend_extension=opcache\n",
                    'opt/homebrew/etc/php/8.3/php-fpm.d/www.conf' => "[www]\nlisten = 127.0.0.1:9000\n",
                    'opt/homebrew/Cellar/php@8.3/8.3.12/bin/.keep' => '',
                    'opt/homebrew/Cellar/php@8.3/8.3.9/bin/.keep' => '',
                ],
                ['opt/homebrew/opt/php@8.3' => '../Cellar/php@8.3/8.3.12'],
                [
                    '/opt/homebrew/etc/php/8.3/php.ini' => ['unknown', '8.3.12', '/opt/homebrew/opt/php@8.3',
                        ['/opt/homebrew/etc/php/8.3/php.ini', '/opt/homebrew/etc/php/8.3/conf.d/ext-opcache.ini']],
                    '/opt/homebrew/etc/php/8.3/php.ini + pool [www] (/opt/homebrew/etc/php/8.3/php-fpm.d/www.conf)'
                        => ['fpm', '8.3.12', null, null],
                ],
            ],
            'cpanel' => [
                [
                    'opt/cpanel/ea-php81/root/etc/php.ini' => "expose_php = On\n",
                    'opt/cpanel/ea-php81/root/etc/php.d/20-curl.ini' => "extension=curl.so\n",
                    'opt/cpanel/ea-php81/root/usr/include/php/main/php_version.h' => self::header('8.1.29'),
                ],
                [],
                [
                    '/opt/cpanel/ea-php81/root/etc/php.ini' => [
                        'unknown', '8.1.29', '/opt/cpanel/ea-php81/root/usr/include/php/main/php_version.h',
                        ['/opt/cpanel/ea-php81/root/etc/php.ini', '/opt/cpanel/ea-php81/root/etc/php.d/20-curl.ini']],
                ],
            ],
            'debian-symlinked-mods' => [
                [
                    'etc/php/8.3/fpm/php.ini' => "expose_php = On\n",
                    'etc/php/8.3/cli/php.ini' => "expose_php = On\n",
                    'etc/php/8.3/mods-available/opcache.ini' => "zend_extension=opcache.so\n",
                    'etc/php/8.3/mods-available/xdebug.ini' => "zend_extension=xdebug.so\n",
                    'etc/php/8.3/fpm/pool.d/www.conf' => "[www]\nlisten = /run/php/php8.3-fpm.sock\n",
                    'var/lib/dpkg/status' => self::dpkg('php8.3-common', '8.3.6-0ubuntu0.24.04.3')
                        . self::dpkg('php8.3-fpm', '8.3.6-0ubuntu0.24.04.3'),
                ],
                [
                    // Debian links enabled modules with absolute targets; they must resolve inside the root.
                    'etc/php/8.3/fpm/conf.d/10-opcache.ini' => '/etc/php/8.3/mods-available/opcache.ini',
                    'etc/php/8.3/cli/conf.d/20-xdebug.ini' => '/etc/php/8.3/mods-available/xdebug.ini',
                ],
                [
                    '/etc/php/8.3/fpm/php.ini' => ['fpm', '8.3.6',
                        '/var/lib/dpkg/status (php8.3-common 8.3.6-0ubuntu0.24.04.3)',
                        ['/etc/php/8.3/fpm/php.ini', '/etc/php/8.3/fpm/conf.d/10-opcache.ini']],
                    '/etc/php/8.3/cli/php.ini' => ['cli', '8.3.6',
                        '/var/lib/dpkg/status (php8.3-common 8.3.6-0ubuntu0.24.04.3)',
                        ['/etc/php/8.3/cli/php.ini', '/etc/php/8.3/cli/conf.d/20-xdebug.ini']],
                    '/etc/php/8.3/fpm/php.ini + pool [www] (/etc/php/8.3/fpm/pool.d/www.conf)'
                        => ['fpm', '8.3.6', null, null],
                ],
            ],
            'bundles' => [
                [
                    'opt/lampp/etc/php.ini' => "expose_php = On\n",
                    'opt/bitnami/php/etc/php.ini' => "expose_php = On\n",
                    'opt/plesk/php/8.2/etc/php.ini' => "expose_php = On\n",
                    'opt/plesk/php/8.2/etc/php.d/opcache.ini' => "zend_extension=opcache.so\n",
                    'Applications/MAMP/bin/php/php8.2.0/conf/php.ini' => "expose_php = On\n",
                ],
                [],
                [
                    '/opt/lampp/etc/php.ini' => ['unknown', null, null, ['/opt/lampp/etc/php.ini']],
                    '/opt/bitnami/php/etc/php.ini' => ['unknown', null, null, ['/opt/bitnami/php/etc/php.ini']],
                    '/opt/plesk/php/8.2/etc/php.ini' => ['unknown', '8.2', 'path',
                        ['/opt/plesk/php/8.2/etc/php.ini', '/opt/plesk/php/8.2/etc/php.d/opcache.ini']],
                    '/Applications/MAMP/bin/php/php8.2.0/conf/php.ini' => ['unknown', '8.2', 'path',
                        ['/Applications/MAMP/bin/php/php8.2.0/conf/php.ini']],
                ],
            ],
        ];
    }

    /**
     * @param array<string, string> $files
     * @param array<string, string> $links
     */
    private static function buildRoot(string $root, array $files, array $links): void
    {
        foreach ($files as $name => $content) {
            Helpers::writeFile("$root/$name", $content);
        }
        foreach ($links as $name => $target) {
            $path = "$root/$name";
            if (!is_dir(dirname($path))) {
                mkdir(dirname($path), 0777, true);
            }
            symlink($target, $path);
        }
    }

    protected function setUp(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('layouts use POSIX symlinks');
        }
    }

    /** @return array<string, array{0: string}> */
    public function layoutNames(): array
    {
        $cases = [];
        foreach (array_keys(self::layouts()) as $layout) {
            $cases[$layout] = [$layout];
        }
        return $cases;
    }

    /** @dataProvider layoutNames */
    public function testLayouts(string $layout): void
    {
        [$files, $links, $expected] = self::layouts()[$layout];
        $root = Helpers::tempDir();
        try {
            self::buildRoot($root, $files, $links);
            [$code, $out, $err] = Helpers::runCli('--root', $root, '--path-checks', 'off', '--format', 'json');
            $this->assertSame(0, $code, $err);
            $report = json_decode($out, true, 512, JSON_THROW_ON_ERROR);
            $this->assertSame([], $report['warnings']);
            $targets = [];
            foreach ($report['targets'] as $target) {
                $targets[$target['name']] = $target;
            }
            $actualNames = array_keys($targets);
            $expectedNames = array_keys($expected);
            sort($actualNames);
            sort($expectedNames);
            $this->assertSame($expectedNames, $actualNames);
            foreach ($expected as $name => [$sapi, $version, $source, $scanned]) {
                $target = $targets[$name];
                $this->assertSame($sapi, $target['sapi'], $name);
                $this->assertSame($version, $target['php_version'], $name);
                if ($source !== null) {
                    $this->assertSame($source, $target['php_version_source'], $name);
                }
                if ($scanned !== null) {
                    $this->assertSame($scanned, $target['files'], $name);
                }
            }
        } finally {
            Helpers::removeTree($root);
        }
    }

    public function testSymlinkOutsideRootIsReanchored(): void
    {
        $root = Helpers::tempDir();
        $outside = Helpers::tempDir();
        try {
            file_put_contents("$outside/evil.ini", "allow_url_include = On\n");
            self::buildRoot($root, ['etc/php/8.3/fpm/php.ini' => "expose_php = Off\n"],
                ['etc/php/8.3/fpm/conf.d/99-evil.ini' => "$outside/evil.ini"]);
            [, $out] = Helpers::runCli('--root', $root, '--path-checks', 'off', '--format', 'json');
            $report = json_decode($out, true, 512, JSON_THROW_ON_ERROR);
            $this->assertNotContains('EXEC-001', array_column($report['findings'], 'rule_id'));
            $this->assertSame(['/etc/php/8.3/fpm/php.ini'], $report['targets'][0]['files']);
        } finally {
            Helpers::removeTree($root);
            Helpers::removeTree($outside);
        }
    }

    public function testDiscoverListsLayout(): void
    {
        [$files, $links] = self::layouts()['alpine'];
        $root = Helpers::tempDir();
        try {
            self::buildRoot($root, $files, $links);
            [$code, $out] = Helpers::runCli('discover', '--root', $root);
            $this->assertSame(0, $code);
            $this->assertStringContainsString('/etc/php83/php.ini  [sapi unknown, php 8.3.12 from /lib/apk/db/installed',
                $out);
            $this->assertStringContainsString('  scan  /etc/php83/conf.d/00_opcache.ini', $out);
            $this->assertStringContainsString('  fpm   /etc/php83/php-fpm.conf', $out);
            $this->assertStringContainsString('  fpm   /etc/php83/php-fpm.d/www.conf', $out);
        } finally {
            Helpers::removeTree($root);
        }
    }
}

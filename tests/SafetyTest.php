<?php

namespace PhpIniAudit\Tests;

use PHPUnit\Framework\TestCase;

/** The scanner must never execute code, spawn processes or touch the network. */
final class SafetyTest extends TestCase
{
    private const SOURCE = __DIR__ . '/../src';
    private const FORBIDDEN_FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec',
        'pcntl_fork', 'posix_kill', 'mail', 'dl', 'assert', 'create_function', 'fsockopen', 'pfsockopen',
        'stream_socket_client', 'stream_socket_server'];
    private const FORBIDDEN_PREFIXES = ['curl_', 'socket_', 'ftp_'];
    private const FORBIDDEN_CLASSES = ['soapclient'];
    private const SKIPPED = [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT];

    public function testNoExecutionPrimitives(): void
    {
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::SOURCE,
            \FilesystemIterator::SKIP_DOTS));
        $problems = [];
        $scanned = 0;
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $scanned++;
                foreach (self::problems((string) file_get_contents($file->getPathname())) as $problem) {
                    $problems[] = $file->getFilename() . ":$problem";
                }
            }
        }
        $this->assertGreaterThan(0, $scanned);
        $this->assertSame([], $problems);
    }

    public function testDetectorCatchesPrimitives(): void
    {
        $code = "<?php\nexec('id');\n\\shell_exec('id');\n`id`;\neval('1;');\nrequire 'x.php';\n"
            . "curl_init();\nnew \\SoapClient(null);\n\$x->exec();\nFoo::system();\nfunction mail() {}\n";
        $this->assertSame(
            ['2: exec()', '3: shell_exec()', '4: backtick', '5: eval', '6: require', '7: curl_init()',
                '8: new SoapClient'],
            self::problems($code)
        );
    }

    /** @return list<string> "line: what" for every forbidden construct in $code */
    private static function problems(string $code): array
    {
        $tokens = [];
        $lines = [];
        $line = 1;
        foreach (token_get_all($code) as $token) {
            if (!is_array($token) || !in_array($token[0], self::SKIPPED, true)) {
                $tokens[] = $token;
                $lines[] = $line;
            }
            $line += substr_count(is_array($token) ? $token[1] : $token, "\n");
        }
        $names = [T_STRING];
        if (defined('T_NAME_FULLY_QUALIFIED')) {
            $names[] = T_NAME_FULLY_QUALIFIED;
        }
        $statements = [T_EVAL => 'eval', T_INCLUDE => 'include', T_INCLUDE_ONCE => 'include_once',
            T_REQUIRE => 'require', T_REQUIRE_ONCE => 'require_once'];
        $problems = [];
        $inShell = false;
        foreach ($tokens as $i => $token) {
            $line = $lines[$i];
            if ($token === '`') {
                if (!$inShell) {
                    $problems[] = "$line: backtick";
                }
                $inShell = !$inShell;
                continue;
            }
            if (!is_array($token)) {
                continue;
            }
            if (isset($statements[$token[0]])) {
                $problems[] = "$line: {$statements[$token[0]]}";
                continue;
            }
            if (!in_array($token[0], $names, true)) {
                continue;
            }
            $name = strtolower(ltrim($token[1], '\\'));
            $previous = self::previous($tokens, $i);
            if ($previous === T_NEW) {
                if (in_array($name, self::FORBIDDEN_CLASSES, true)) {
                    $problems[] = "$line: new " . ltrim($token[1], '\\');
                }
                continue;
            }
            if (($tokens[$i + 1] ?? null) !== '(' || in_array($previous, [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION],
                    true)) {
                continue;
            }
            if (defined('T_NULLSAFE_OBJECT_OPERATOR') && $previous === T_NULLSAFE_OBJECT_OPERATOR) {
                continue;
            }
            if (in_array($name, self::FORBIDDEN_FUNCTIONS, true) || self::hasForbiddenPrefix($name)) {
                $problems[] = "$line: $name()";
            }
        }
        return $problems;
    }

    /**
     * Type of the significant token before $i, looking through a leading "\" (PHP 7.4 tokenises \exec as two tokens).
     * Returns the "\" itself for a namespace-qualified name such as Foo\exec, which is not a global call.
     *
     * @param list<array|string> $tokens
     * @return int|string|null
     */
    private static function previous(array $tokens, int $i)
    {
        $type = static function ($token) {
            return is_array($token) ? $token[0] : $token;
        };
        $previous = $i > 0 ? $type($tokens[$i - 1]) : null;
        if ($previous === T_NS_SEPARATOR) {
            $before = $i > 1 ? $type($tokens[$i - 2]) : null;
            return $before === T_STRING || $before === T_NAMESPACE ? T_NS_SEPARATOR : $before;
        }
        return $previous;
    }

    private static function hasForbiddenPrefix(string $name): bool
    {
        foreach (self::FORBIDDEN_PREFIXES as $prefix) {
            if (strncmp($name, $prefix, strlen($prefix)) === 0) {
                return true;
            }
        }
        return false;
    }
}

<?php

namespace PhpIniAudit;

use PhpIniAudit\Rules\Registry;

/** Command-line interface. */
final class Cli
{
    public const COMMANDS = ['scan', 'rules', 'discover'];
    public const SAPIS = ['cli', 'fpm', 'apache2', 'cgi', 'litespeed', 'embed', 'unknown'];
    public const EXIT_OK = 0;
    public const EXIT_FINDINGS = 1;
    public const EXIT_USAGE = 2;

    private const PROG = 'php-ini-audit';

    private const MAIN_USAGE = "usage: php-ini-audit [-h] [--version] {scan,rules,discover} ...\n";
    private const MAIN_HELP = <<<'TXT'

Statically audit PHP INI configuration. Files are only read; nothing is
executed.

positional arguments:
  {scan,rules,discover}
    scan                audit configuration (default command)
    rules               list the rule catalogue or explain one rule
    discover            list the configuration files that would be audited

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

TXT;

    private const SCAN_USAGE = <<<'TXT'
usage: php-ini-audit scan [-h] [--root ROOT] [--ini INI] [--scan-dir SCAN_DIR]
                          [--pool POOL] [--webroot WEBROOT]
                          [--max-depth MAX_DEPTH] [--phpinfo FILE]
                          [--profile {production,development}]
                          [--sapi {cli,fpm,apache2,cgi,litespeed,embed,unknown}]
                          [--php-version PHP_VERSION]
                          [--path-checks {auto,on,off}]
                          [--min-severity MIN_SEVERITY] [--only ONLY]
                          [--skip SKIP] [--format {text,json,sarif,markdown}]
                          [-o OUTPUT] [--fail-on FAIL_ON] [--no-color]
                          [paths ...]

TXT;

    private const SOURCE_HELP = <<<'TXT'

positional arguments:
  paths                 php.ini / *.ini / pool *.conf / .user.ini / .htaccess
                        files or directories to walk; omit to discover system
                        installations

options:
  -h, --help            show this help message and exit
  --root ROOT           audit a mounted filesystem or container image
                        extracted at this path
  --ini INI             explicit php.ini (like php -c)
  --scan-dir SCAN_DIR   extra INI scan directory (like PHP_INI_SCAN_DIR);
                        repeatable
  --pool POOL           php-fpm pool or php-fpm.conf; repeatable
  --webroot WEBROOT     document root: its .user.ini/.htaccess files are
                        audited and paths inside it are treated as web-served;
                        repeatable
  --max-depth MAX_DEPTH
                        directory walk depth (default 12)

TXT;

    private const SCAN_HELP = <<<'TXT'
  --phpinfo FILE        audit saved phpinfo() HTML or `php -i` output instead
                        of configuration files; - reads stdin
  --profile {production,development}
                        severity profile (default production)
  --sapi {cli,fpm,apache2,cgi,litespeed,embed,unknown}
                        override the SAPI inferred from paths
  --php-version PHP_VERSION
                        exact PHP version (X.Y or X.Y.Z); otherwise read from
                        paths, headers and package databases
  --path-checks {auto,on,off}
                        inspect permissions of referenced paths; auto = on for
                        system/--root scans
  --min-severity MIN_SEVERITY
                        hide findings below this
  --only ONLY           rule id or category (e.g. SESS); repeatable
  --skip SKIP           rule id or category to skip; repeatable
  --format {text,json,sarif,markdown}
  -o, --output OUTPUT   write the report to this file
  --fail-on FAIL_ON     exit 1 when a finding at or above this severity exists
  --no-color

TXT;

    private const RULES_USAGE = "usage: php-ini-audit rules [-h] [--format {text,json,markdown}] [rule_id]\n";
    private const RULES_HELP = <<<'TXT'

positional arguments:
  rule_id

options:
  -h, --help            show this help message and exit
  --format {text,json,markdown}

TXT;

    private const DISCOVER_USAGE = <<<'TXT'
usage: php-ini-audit discover [-h] [--root ROOT] [--ini INI]
                              [--scan-dir SCAN_DIR] [--pool POOL]
                              [--webroot WEBROOT] [--max-depth MAX_DEPTH]
                              [paths ...]

TXT;

    /** @return list<array<string, mixed>> option specs in definition order */
    private static function sourceOptions(): array
    {
        return [
            ['dest' => 'root', 'flags' => ['--root']],
            ['dest' => 'ini', 'flags' => ['--ini']],
            ['dest' => 'scan_dir', 'flags' => ['--scan-dir'], 'append' => true],
            ['dest' => 'pool', 'flags' => ['--pool'], 'append' => true],
            ['dest' => 'webroot', 'flags' => ['--webroot'], 'append' => true],
            ['dest' => 'max_depth', 'flags' => ['--max-depth'], 'type' => 'int', 'default' => 12],
        ];
    }

    /** @return array{prog: string, usage: string, help: string, options: list<array>, positional: array} */
    private static function subparser(string $command): array
    {
        $help = ['dest' => 'help', 'flags' => ['-h', '--help'], 'action' => 'help'];
        if ($command === 'rules') {
            return [
                'prog' => self::PROG . ' rules',
                'usage' => self::RULES_USAGE,
                'help' => self::RULES_USAGE . self::RULES_HELP,
                'options' => [
                    $help,
                    ['dest' => 'format', 'flags' => ['--format'], 'choices' => ['text', 'json', 'markdown'],
                        'default' => 'text'],
                ],
                'positional' => ['dest' => 'rule_id', 'nargs' => '?'],
            ];
        }
        $options = array_merge([$help], self::sourceOptions());
        $positional = ['dest' => 'paths', 'nargs' => '*'];
        if ($command === 'discover') {
            return [
                'prog' => self::PROG . ' discover',
                'usage' => self::DISCOVER_USAGE,
                'help' => self::DISCOVER_USAGE . self::SOURCE_HELP,
                'options' => $options,
                'positional' => $positional,
            ];
        }
        array_push($options,
            ['dest' => 'phpinfo', 'flags' => ['--phpinfo']],
            ['dest' => 'profile', 'flags' => ['--profile'], 'choices' => Auditor::PROFILES, 'default' => 'production'],
            ['dest' => 'sapi', 'flags' => ['--sapi'], 'choices' => self::SAPIS],
            ['dest' => 'php_version', 'flags' => ['--php-version'], 'type' => 'version'],
            ['dest' => 'path_checks', 'flags' => ['--path-checks'], 'choices' => ['auto', 'on', 'off'],
                'default' => 'auto'],
            ['dest' => 'min_severity', 'flags' => ['--min-severity'], 'type' => 'severity',
                'default' => Severity::INFO],
            ['dest' => 'only', 'flags' => ['--only'], 'append' => true],
            ['dest' => 'skip', 'flags' => ['--skip'], 'append' => true],
            ['dest' => 'format', 'flags' => ['--format'], 'choices' => ['text', 'json', 'sarif', 'markdown'],
                'default' => 'text'],
            ['dest' => 'output', 'flags' => ['-o', '--output']],
            ['dest' => 'fail_on', 'flags' => ['--fail-on'], 'type' => 'severity'],
            ['dest' => 'no_color', 'flags' => ['--no-color'], 'action' => 'store_true']
        );
        return [
            'prog' => self::PROG . ' scan',
            'usage' => self::SCAN_USAGE,
            'help' => rtrim(self::SCAN_USAGE . self::SOURCE_HELP, "\n") . "\n" . self::SCAN_HELP,
            'options' => $options,
            'positional' => $positional,
        ];
    }

    private static function write(string $stream, string $text): void
    {
        $constant = $stream === 'stdout' ? 'STDOUT' : 'STDERR';
        if (defined($constant)) {
            fwrite(constant($constant), $text);
            return;
        }
        $handle = fopen("php://$stream", 'w');
        fwrite($handle, $text);
        fclose($handle);
    }

    private static function out(string $text): void
    {
        self::write('stdout', $text);
    }

    private static function err(string $text): void
    {
        self::write('stderr', $text);
    }

    /** Recognise an option token: [spec|null, flag, explicit value|null, attached?]. */
    private static function parseOptional(string $token, array $options): ?array
    {
        if ($token === '' || $token[0] !== '-') {
            return null;
        }
        $byFlag = [];
        foreach ($options as $spec) {
            foreach ($spec['flags'] as $flag) {
                $byFlag[$flag] = $spec;
            }
        }
        if (isset($byFlag[$token])) {
            return [$byFlag[$token], $token, null];
        }
        if (strlen($token) === 1) {
            return null;
        }
        if (Util::contains($token, '=')) {
            [$flag, $explicit] = explode('=', $token, 2);
            if (isset($byFlag[$flag])) {
                return [$byFlag[$flag], $flag, $explicit];
            }
        }
        $matches = [];
        if (Util::startsWith($token, '--')) {
            $parts = explode('=', $token, 2);
            foreach ($byFlag as $flag => $spec) {
                if (Util::startsWith((string) $flag, $parts[0])) {
                    $matches[] = [$spec, (string) $flag, $parts[1] ?? null];
                }
            }
        } else {
            $short = substr($token, 0, 2);
            foreach ($byFlag as $flag => $spec) {
                if ((string) $flag === $short) {
                    $matches[] = [$spec, $short, substr($token, 2), true];
                } elseif (Util::startsWith((string) $flag, $token)) {
                    $matches[] = [$spec, (string) $flag, null];
                }
            }
        }
        if (count($matches) > 1) {
            $names = implode(', ', array_column($matches, 1));
            throw new \UnexpectedValueException("ambiguous option: $token could match $names");
        }
        if (count($matches) === 1) {
            return $matches[0];
        }
        if (preg_match('/^-\d+$|^-\d*\.\d+$/', $token) || Util::contains($token, ' ')) {
            return null;
        }
        return [null, $token, null];
    }

    /** @return mixed */
    private static function convert(array $spec, string $value)
    {
        $type = $spec['type'] ?? null;
        if ($type === 'int') {
            if (!preg_match('/^\s*[+-]?\d+(?:_\d+)*\s*$/D', $value)) {
                throw new \UnexpectedValueException("invalid int value: " . Util::repr($value));
            }
            $value = (int) str_replace('_', '', trim($value));
        } elseif ($type === 'version') {
            if (!preg_match('/^\d+\.\d+(\.\d+)?\z/', $value)) {
                throw new \UnexpectedValueException('expected MAJOR.MINOR or MAJOR.MINOR.PATCH, e.g. 8.3.12');
            }
            $value = Versions::parseVersion($value);
        } elseif ($type === 'severity') {
            try {
                $value = Severity::parse($value);
            } catch (\InvalidArgumentException $exception) {
                throw new \UnexpectedValueException($exception->getMessage());
            }
        }
        if (isset($spec['choices']) && !in_array($value, $spec['choices'], true)) {
            $choices = implode(', ', array_map([Util::class, 'repr'], $spec['choices']));
            throw new \UnexpectedValueException('invalid choice: ' . Util::repr($value) . " (choose from $choices)");
        }
        return $value;
    }

    /**
     * Parse a subcommand's arguments; returns [args, unrecognised tokens] or prints help.
     * @return array{0: array<string, mixed>, 1: list<string>}|null null when help was printed
     */
    private static function parseCommand(array $parser, array $argv): ?array
    {
        $items = [];
        $positionalOnly = false;
        foreach ($argv as $token) {
            $token = (string) $token;
            if (!$positionalOnly && $token === '--') {
                $positionalOnly = true;
                continue;
            }
            $items[] = [$token, $positionalOnly ? null : self::parseOptional($token, $parser['options'])];
        }

        $args = [];
        foreach ($parser['options'] as $spec) {
            if (($spec['action'] ?? null) === 'help') {
                continue;
            }
            if (!empty($spec['append'])) {
                $args[$spec['dest']] = [];
            } elseif (($spec['action'] ?? null) === 'store_true') {
                $args[$spec['dest']] = false;
            } else {
                $args[$spec['dest']] = $spec['default'] ?? null;
            }
        }
        $positional = $parser['positional'];
        $positionalDone = false;
        $args[$positional['dest']] = $positional['nargs'] === '*' ? [] : null;
        $extras = [];
        $count = count($items);
        for ($i = 0; $i < $count; $i++) {
            [$token, $optional] = $items[$i];
            if ($optional === null) {
                $run = [];
                while ($i < $count && $items[$i][1] === null) {
                    $run[] = $items[$i][0];
                    $i++;
                }
                $i--;
                if ($positionalDone) {
                    array_push($extras, ...$run);
                } elseif ($positional['nargs'] === '*') {
                    $args[$positional['dest']] = $run;
                    $positionalDone = true;
                } else {
                    $args[$positional['dest']] = array_shift($run);
                    array_push($extras, ...$run);
                    $positionalDone = true;
                }
                continue;
            }
            [$spec, $flag, $explicit] = $optional;
            $attached = $optional[3] ?? false;
            if ($spec === null) {
                $extras[] = $token;
                continue;
            }
            $name = implode('/', $spec['flags']);
            $action = $spec['action'] ?? 'store';
            if ($action === 'help' || $action === 'store_true') {
                // "-hx" is the flag -h followed by more single-letter flags.
                $combined = $attached && $explicit !== '';
                if ($explicit !== null && !($combined && $action === 'help')) {
                    throw new \UnexpectedValueException("argument $name: ignored explicit argument " . Util::repr($explicit));
                }
                if ($action === 'help') {
                    self::out($parser['help']);
                    return null;
                }
                $args[$spec['dest']] = true;
                continue;
            }
            if ($explicit === null) {
                if ($i + 1 >= $count || $items[$i + 1][1] !== null) {
                    throw new \UnexpectedValueException("argument $name: expected one argument");
                }
                $explicit = $items[++$i][0];
            }
            try {
                $value = self::convert($spec, $explicit);
            } catch (\UnexpectedValueException $error) {
                throw new \UnexpectedValueException("argument $name: " . $error->getMessage());
            }
            if (!empty($spec['append'])) {
                $args[$spec['dest']][] = $value;
            } else {
                $args[$spec['dest']] = $value;
            }
        }
        return [$args, $extras];
    }

    /** @param list<string> $argv arguments without the program name */
    public static function main(array $argv): int
    {
        $argv = array_values(array_map('strval', $argv));
        if (!$argv || (!in_array($argv[0], self::COMMANDS, true)
                && !in_array($argv[0], ['-h', '--help', '--version'], true))) {
            array_unshift($argv, 'scan');
        }
        if ($argv[0] === '-h' || $argv[0] === '--help') {
            self::out(self::MAIN_USAGE . self::MAIN_HELP);
            return self::EXIT_OK;
        }
        if ($argv[0] === '--version') {
            self::out(self::PROG . ' ' . Version::VERSION . "\n");
            return self::EXIT_OK;
        }
        $parser = self::subparser($argv[0]);
        try {
            $parsed = self::parseCommand($parser, array_slice($argv, 1));
        } catch (\UnexpectedValueException $error) {
            self::err($parser['usage'] . "{$parser['prog']}: error: {$error->getMessage()}\n");
            return self::EXIT_USAGE;
        }
        if ($parsed === null) {
            return self::EXIT_OK;
        }
        [$args, $extras] = $parsed;
        if ($extras) {
            self::err(self::MAIN_USAGE . self::PROG . ': error: unrecognized arguments: ' . implode(' ', $extras) . "\n");
            return self::EXIT_USAGE;
        }
        $args['command'] = $argv[0];

        if ($args['command'] === 'rules') {
            return self::cmdRules($args);
        }
        $root = $args['root'];
        if ($root !== null && $root !== '' && !is_dir($root)) {
            self::err("--root $root is not a directory\n");
            return self::EXIT_USAGE;
        }
        $fs = new FileSystem($root === '' ? null : $root);
        try {
            if ($args['command'] === 'discover') {
                return self::cmdDiscover($args, $fs);
            }
            return self::cmdScan($args, $fs);
        } catch (\InvalidArgumentException | ReadError $exception) {
            self::err("error: {$exception->getMessage()}\n");
            return self::EXIT_USAGE;
        }
    }

    /** With --root, accept both host paths below the root and paths as seen inside it. */
    private static function displayPath(FileSystem $fs, string $path): string
    {
        if ($fs->root === null) {
            return Paths::abspath($path);
        }
        $absolute = Paths::abspath($path);
        if ($absolute === $fs->root || Util::startsWith($absolute, rtrim($fs->root, '/') . '/')) {
            return $fs->toDisplay($absolute);
        }
        return '/' . ltrim($path, '/');
    }

    private static function discover(array $args, FileSystem $fs): Discovery
    {
        $discoverer = new Discoverer($fs);
        $display = static function (string $path) use ($fs): string {
            return self::displayPath($fs, $path);
        };

        $paths = array_map($display, $args['paths']);
        $ini = $args['ini'];
        $hasIni = $ini !== null && $ini !== '';
        $explicit = $paths || $hasIni || $args['scan_dir'] || $args['pool'];
        $discovery = $paths ? $discoverer->paths($paths, $args['max_depth']) : new Discovery();
        if ($hasIni || $args['scan_dir']) {
            $iniPath = $hasIni ? $display($ini) : null;
            $directory = $iniPath !== null ? Paths::osDirname($iniPath) : $display($args['scan_dir'][0]);
            $installation = $discoverer->build($iniPath, $directory, array_map($display, $args['scan_dir']));
            $installation->fpmFiles = array_map($display, $args['pool']);
            $discovery->installations[] = $installation;
        } elseif ($args['pool']) {
            $extra = $discoverer->paths(array_map($display, $args['pool']));
            array_push($discovery->installations, ...$extra->installations);
        }
        if (!$explicit) {
            $discovery = $discoverer->system();
        }
        if (!$explicit || $fs->root !== null) {
            $discovery->resolveVersions($fs);
        }
        foreach ($args['webroot'] as $webroot) {
            $found = $discoverer->paths([$display($webroot)], $args['max_depth']);
            foreach ($found->userInis as $path) {
                if (!in_array($path, $discovery->userInis, true)) {
                    $discovery->userInis[] = $path;
                }
            }
            foreach ($found->htaccess as $path) {
                if (!in_array($path, $discovery->htaccess, true)) {
                    $discovery->htaccess[] = $path;
                }
            }
            array_push($discovery->warnings, ...$found->warnings);
        }
        return $discovery;
    }

    private static function cmdRules(array $args): int
    {
        $ruleIdArg = $args['rule_id'];
        if ($ruleIdArg !== null && $ruleIdArg !== '') {
            $ruleId = strtoupper($ruleIdArg);
            if (!array_key_exists($ruleId, Registry::all())) {
                self::err("unknown rule: $ruleIdArg\n");
                return self::EXIT_USAGE;
            }
            self::out(Report::renderRule($ruleId));
        } else {
            self::out(Report::renderRules($args['format']));
        }
        return self::EXIT_OK;
    }

    private static function cmdDiscover(array $args, FileSystem $fs): int
    {
        $discovery = self::discover($args, $fs);
        foreach ($discovery->installations as $installation) {
            $version = Versions::formatVersion($installation->phpVersion);
            if ($installation->versionSource !== null && $installation->versionSource !== '') {
                $version .= " from {$installation->versionSource}";
            }
            self::out("{$installation->label}  [sapi {$installation->sapi}, php $version]\n");
            if ($installation->defaultsReason !== null && $installation->defaultsReason !== '') {
                self::out("  ! {$installation->defaultsReason}\n");
            }
            foreach ($installation->scanFiles as $path) {
                self::out("  scan  $path\n");
            }
            foreach ($installation->fpmFiles as $path) {
                self::out("  fpm   $path\n");
            }
        }
        foreach ($discovery->userInis as $path) {
            self::out(".user.ini  $path\n");
        }
        foreach ($discovery->htaccess as $path) {
            self::out(".htaccess  $path\n");
        }
        foreach ($discovery->warnings as $warning) {
            self::err("warning: $warning\n");
        }
        if (!($discovery->installations || $discovery->userInis || $discovery->htaccess)) {
            self::err("No PHP configuration found.\n");
        }
        return self::EXIT_OK;
    }

    private static function cmdScan(array $args, FileSystem $fs): int
    {
        $registry = Registry::all();
        $categories = [];
        foreach ($registry as $rule) {
            $categories[$rule->category()] = true;
        }
        foreach (array_merge($args['only'], $args['skip']) as $selector) {
            $upper = strtoupper($selector);
            if (!array_key_exists($upper, $registry) && !array_key_exists($upper, $categories)) {
                self::err("unknown rule or category: $selector\n");
                return self::EXIT_USAGE;
            }
        }
        $options = new Options();
        $options->profile = $args['profile'];
        $options->sapi = $args['sapi'];
        $options->phpVersion = $args['php_version'];
        $options->minSeverity = $args['min_severity'];
        $options->only = $args['only'];
        $options->skip = $args['skip'];
        $phpinfo = $args['phpinfo'];
        if ($phpinfo !== null && $phpinfo !== '') {
            if ($phpinfo === '-') {
                // Read stdin with universal newlines.
                $text = str_replace(["\r\n", "\r"], "\n", (string) file_get_contents('php://stdin'));
            } else {
                $text = $fs->readText(self::displayPath($fs, $phpinfo));
            }
            return self::report($args, Phpinfo::audit($text, $options));
        }
        $discovery = self::discover($args, $fs);
        $systemScan = !($args['paths'] || ($args['ini'] !== null && $args['ini'] !== '') || $args['scan_dir']
            || $args['pool']);
        $options->pathChecks = $args['path_checks'] === 'on'
            || ($args['path_checks'] === 'auto' && ($systemScan || ($args['root'] !== null && $args['root'] !== '')));
        $options->webroots = array_map(static function (string $w) use ($fs): string {
            return self::displayPath($fs, $w);
        }, $args['webroot']);
        return self::report($args, (new Auditor($fs, $options))->run($discovery));
    }

    private static function isatty(): bool
    {
        $stdout = defined('STDOUT') ? STDOUT : null;
        if ($stdout === null) {
            return false;
        }
        if (function_exists('stream_isatty')) {
            return stream_isatty($stdout);
        }
        return function_exists('posix_isatty') && posix_isatty($stdout);
    }

    private static function report(array $args, AuditResult $result): int
    {
        $output = $args['output'];
        $toFile = $output !== null && $output !== '';
        if ($args['format'] === 'json') {
            $text = Report::renderJson($result, $args['profile']);
        } elseif ($args['format'] === 'sarif') {
            $text = Report::renderSarif($result, $args['profile']);
        } elseif ($args['format'] === 'markdown') {
            $text = Report::renderMarkdown($result, $args['profile']);
        } else {
            $color = !$args['no_color'] && !$toFile && self::isatty() && getenv('NO_COLOR') === false;
            $text = Report::renderText($result, $args['profile'], $color);
        }

        if ($toFile) {
            if (@file_put_contents($output, $text) === false) {
                self::err("error: cannot write $output\n");
                return self::EXIT_FINDINGS;
            }
        } else {
            self::out($text);
        }

        if ($args['fail_on'] !== null) {
            foreach ($result->findings as $finding) {
                if ($finding->severity >= $args['fail_on']) {
                    return self::EXIT_FINDINGS;
                }
            }
        }
        return self::EXIT_OK;
    }
}

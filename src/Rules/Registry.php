<?php

namespace PhpIniAudit\Rules;

/** Every rule, one class each, grouped by category in Category::NAMES order. */
final class Registry
{
    private const RULES = [
        'EXEC' => [
            Execution\RemoteFileInclusion::class,
            Execution\RemoteUrlFopen::class,
            Execution\StreamWrapperAutoPrepend::class,
            Execution\AutoPrependedCode::class,
            Execution\CommandExecutionFunctions::class,
            Execution\DisableFunctionsBypass::class,
            Execution\FfiEnabled::class,
            Execution\RuntimeExtensionLoading::class,
            Execution\WritablePhar::class,
            Execution\UnsignedPhar::class,
            Execution\QueryStringAsArgv::class,
            Execution\ImapInsecureRsh::class,
            Execution\DangerousSendmailOptions::class,
            Execution\ProductionAssertions::class,
            Execution\UnserializeCallback::class,
            Execution\CurrentDirectoryInIncludePath::class,
            Execution\SessionUploadProgress::class,
        ],
        'FS' => [
            Filesystem\OpenBasedirUnset::class,
            Filesystem\OpenBasedirWholeFilesystem::class,
            Filesystem\OpenBasedirPrefixMatch::class,
            Filesystem\OpenBasedirRelativeEntries::class,
            Filesystem\WorldWritablePath::class,
            Filesystem\WebServedPath::class,
            Filesystem\MissingPath::class,
            Filesystem\UserIniOverrides::class,
            Filesystem\FileUploadsEnabled::class,
            Filesystem\SharedUploadTempDir::class,
            Filesystem\WritableConfigFile::class,
        ],
        'ERR' => [
            Disclosure\DisplayErrors::class,
            Disclosure\DisplayStartupErrors::class,
            Disclosure\ErrorsNotLogged::class,
            Disclosure\ExposePhp::class,
            Disclosure\ExceptionArgumentsInTraces::class,
            Disclosure\ErrorReportingDisabled::class,
            Disclosure\MailScriptHeader::class,
            Disclosure\EnvironmentInSuperglobal::class,
            Disclosure\WorldWritableErrorLog::class,
            Disclosure\PhpinfoCallable::class,
            Disclosure\LongTraceArguments::class,
        ],
        'SESS' => [
            Session\StrictModeOff::class,
            Session\IdsOutsideCookies::class,
            Session\TransparentIds::class,
            Session\CookiesDisabled::class,
            Session\CookieWithoutHttpOnly::class,
            Session\CookieWithoutSecure::class,
            Session\CookieWithoutSameSite::class,
            Session\WeakIdEntropy::class,
            Session\SharedSaveDirectory::class,
            Session\PermissiveFileMode::class,
            Session\LongLivedSessions::class,
            Session\DefaultCookieName::class,
            Session\PersistentCookie::class,
            Session\SharedCookieDomain::class,
        ],
        'RES' => [
            Resources\MemoryLimit::class,
            Resources\ExecutionTime::class,
            Resources\PostSize::class,
            Resources\UploadSize::class,
            Resources\InputVars::class,
            Resources\InputNesting::class,
            Resources\FileUploadCount::class,
            Resources\RegexLimits::class,
            Resources\UnserializeDepth::class,
            Resources\SocketTimeout::class,
            Resources\MultipartBodyParts::class,
        ],
        'CGI' => [
            Cgi\ForceRedirectOff::class,
            Cgi\FixPathinfo::class,
        ],
        'EXT' => [
            Extensions\XdebugClientDiscovery::class,
            Extensions\XdebugLoaded::class,
            Extensions\DevelopmentExtensions::class,
        ],
        'OPC' => [
            Opcache\FileCache::class,
            Opcache\UnrestrictedApi::class,
            Opcache\NoUserIsolation::class,
        ],
        'DB' => [
            Database\LoadDataLocal::class,
            Database\StoredCredentials::class,
            Database\RelaxedSqlite::class,
        ],
        'ENC' => [
            Encoding\UnsafeDefaultCharset::class,
            Encoding\FunctionOverloading::class,
            Encoding\MultibyteScripts::class,
            Encoding\InputEncodingTranslation::class,
        ],
        'CFG' => [
            Hygiene\SyntaxProblem::class,
            Hygiene\ObsoleteDirective::class,
            Hygiene\MisspelledDirective::class,
            Hygiene\RedefinedDirective::class,
            Hygiene\IgnoredOverride::class,
            Hygiene\BuiltinDefaults::class,
            Hygiene\EnvironmentValue::class,
            Hygiene\DevelopmentConfig::class,
            Hygiene\ConditionalSection::class,
            Hygiene\DeprecatedDirective::class,
        ],
        'FPM' => [
            Fpm\NetworkListener::class,
            Fpm\NonPhpExtensions::class,
            Fpm\WorldWritableSocket::class,
            Fpm\RootWorkers::class,
            Fpm\StatusEndpoint::class,
            Fpm\FullEnvironment::class,
            Fpm\LiteralSecret::class,
            Fpm\DumpableWorkers::class,
        ],
        'HTA' => [
            Htaccess\NonPhpHandler::class,
        ],
        'VULN' => [
            Version\UnsupportedBranch::class,
            Version\UnknownPatchLevel::class,
            Version\DisclosedCves::class,
        ],
        'CVE' => [
            Cve\FpmOpcacheAccessBypass::class,
            Cve\ImapOpenCommandInjection::class,
            Cve\FpmPathInfoUnderflow::class,
            Cve\UploadTempFileLeak::class,
            Cve\UploadProgressCrash::class,
            Cve\EncodedCookieNames::class,
            Cve\FpmPrivilegeEscalation::class,
            Cve\HostCookieSpoofing::class,
            Cve\MultipartDos::class,
            Cve\ProcOpenWindowsInjection::class,
            Cve\CookiePrefixBypass::class,
            Cve\CgiWindowsArgumentInjection::class,
            Cve\ProcOpenWindowsInjectionBypass::class,
            Cve\MultipartParsing::class,
            Cve\CgiWindowsArgumentInjectionBypass::class,
            Cve\ForceRedirectBypass::class,
            Cve\FpmLogTampering::class,
            Cve\StreamProxyCrlfInjection::class,
            Cve\HttpFoldedHeaders::class,
            Cve\LibxmlRedirectContentType::class,
            Cve\HttpHeaderWithoutColon::class,
            Cve\HttpAuthorizationHeaderCheck::class,
            Cve\HttpRedirectTruncation::class,
            Cve\FpmStatusPageXss::class,
            Cve\HttpRedirectCredentialLeak::class,
            Cve\AllowedClientsIpv6Bypass::class,
            Cve\HttpEmptyRedirectRead::class,
            Cve\OutOfMemoryRce::class,
            Cve\StaleRequestStateRce::class,
        ],
    ];

    /** @var array<string, Rule>|null */
    private static ?array $rules = null;

    /** @return array<string, Rule> rule id => rule, in registration order */
    public static function all(): array
    {
        if (self::$rules === null) {
            $rules = [];
            foreach (self::RULES as $category => $classes) {
                foreach ($classes as $class) {
                    $rule = new $class();
                    self::validate($rule, $category, $rules);
                    $rules[$rule->id] = $rule;
                }
            }
            self::$rules = $rules;
        }
        return self::$rules;
    }

    public static function get(string $id): ?Rule
    {
        return self::all()[$id] ?? null;
    }

    /** @return list<Advisory> */
    public static function advisories(): array
    {
        return array_values(array_filter(self::all(), static function (Rule $rule): bool {
            return $rule instanceof Advisory;
        }));
    }

    public static function advisory(string $cve): ?Advisory
    {
        $rule = self::get($cve);
        return $rule instanceof Advisory ? $rule : null;
    }

    /** @return list<string> */
    public static function securityDirectives(): array
    {
        $names = [];
        foreach (self::all() as $rule) {
            foreach ($rule->directives as $name) {
                $names[$name] = true;
            }
        }
        return array_map('strval', array_keys($names));
    }

    /** @param array<string, Rule> $registered */
    private static function validate(Rule $rule, string $category, array $registered): void
    {
        $class = get_class($rule);
        if (isset($registered[$rule->id])) {
            throw new \LogicException("duplicate rule id {$rule->id}");
        }
        if ($rule->category() !== $category) {
            throw new \LogicException("$class: {$rule->id} is listed under $category");
        }
        if (strpos($class, __NAMESPACE__ . '\\' . Category::NAMESPACES[$category] . '\\') !== 0) {
            throw new \LogicException("$class: $category rules belong in namespace " . Category::NAMESPACES[$category]);
        }
    }
}

<?php

namespace PhpIniAudit\Rules\Cve;

use PhpIniAudit\Rules\Advisory;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class AllowedClientsIpv6Bypass extends Advisory
{
    public const ID = 'CVE-2026-91768';
    public const TITLE = 'IPv6 bypass of listen.allowed_clients';
    public const SEVERITY = Severity::HIGH;
    public const SCOPE = 'pool';
    public const CWE = 'CWE-284';
    public const FIXED = ['8.2.34', '8.3.35', '8.4.26', '8.5.11'];
    public const DESCRIPTION = 'listen.allowed_clients compares IPv6 addresses partially, so clients outside the list '
        . 'can reach the unauthenticated FastCGI port.';
    public const RECOMMENDATION = 'Upgrade; also firewall the FastCGI port or use a Unix socket.';

    public function exposure(Context $ctx): ?Exposure
    {
        $listen = $ctx->pool->settings['listen'] ?? null;
        $allowed = $ctx->pool->settings['listen.allowed_clients'] ?? null;
        if ($listen !== null && !Util::startsWith($listen->value, '/') && $allowed !== null
            && trim($allowed->value) !== '') {
            return new Exposure("TCP listener restricted only by listen.allowed_clients = {$allowed->value}",
                [$allowed, $listen]);
        }
        return null;
    }
}

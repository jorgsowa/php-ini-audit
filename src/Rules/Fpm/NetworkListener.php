<?php

namespace PhpIniAudit\Rules\Fpm;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\PoolRule;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class NetworkListener extends PoolRule
{
    public const ID = 'FPM-001';
    public const TITLE = 'FastCGI port reachable from the network';
    public const SEVERITY = Severity::CRITICAL;
    public const CWE = 'CWE-306';
    public const DESCRIPTION = 'FastCGI has no authentication. Anyone who reaches the port can pass PHP_VALUE / '
        . 'PHP_ADMIN_VALUE (e.g. auto_prepend_file = php://input) and execute code.';
    public const RECOMMENDATION = 'Listen on a Unix socket or 127.0.0.1, and set listen.allowed_clients; never '
        . 'publish the port outside the host or container network.';

    private const LOOPBACK = '/^(127\.\d+\.\d+\.\d+|::1|\[::1\]|localhost)$/i';

    public function check(Context $ctx): iterable
    {
        $listen = $ctx->pool->settings['listen'] ?? null;
        if ($listen === null) {
            return;
        }
        $address = trim($listen->value);
        if (Util::startsWith($address, '/') || $address === '') {
            return;
        }
        if (ctype_digit($address)) {
            $host = '*';
        } else {
            $colon = strrpos($address, ':');
            $host = $colon !== false ? substr($address, 0, $colon) : $address;
        }
        $host = trim($host);
        if (preg_match(self::LOOPBACK, $host)) {
            return;
        }
        $allowed = $ctx->pool->settings['listen.allowed_clients'] ?? null;
        $allInterfaces = in_array($host, ['*', '0.0.0.0', '[::]', '::'], true);
        if ($allowed !== null && trim($allowed->value) !== '') {
            yield new Hit(
                "listen = $address; restricted by listen.allowed_clients = {$allowed->value}",
                [$listen, $allowed],
                Severity::MEDIUM
            );
        } elseif ($allInterfaces) {
            yield new Hit(
                "listen = $address binds every interface without listen.allowed_clients",
                [$listen],
                null,
                Confidence::MEDIUM
            );
        } else {
            yield new Hit("listen = $address without listen.allowed_clients", [$listen], Severity::HIGH,
                Confidence::MEDIUM);
        }
    }
}

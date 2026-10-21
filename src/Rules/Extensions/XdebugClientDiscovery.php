<?php

namespace PhpIniAudit\Rules\Extensions;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Severity;
use PhpIniAudit\Util;

final class XdebugClientDiscovery extends ConfigRule
{
    public const ID = 'EXT-001';
    public const TITLE = 'Xdebug accepts debugger connections for any client';
    public const SEVERITY = Severity::CRITICAL;
    public const DEV_SEVERITY = Severity::HIGH;
    public const DIRECTIVES = ['xdebug.mode', 'xdebug.discover_client_host', 'xdebug.remote_enable',
        'xdebug.remote_connect_back'];
    public const CWE = 'CWE-489';
    public const DESCRIPTION = 'With discover_client_host (Xdebug 3) or remote_connect_back (Xdebug 2), Xdebug '
        . 'connects back to whoever sent the request and hands them a debugger that can evaluate arbitrary PHP.';
    public const RECOMMENDATION = 'Never enable client discovery on reachable hosts; remove Xdebug from production.';
    public const REFERENCES = ['https://xdebug.org/docs/all_settings#discover_client_host'];

    public function check(Context $ctx): iterable
    {
        if (!($ctx->loadedExtension('xdebug') !== null || self::xdebugSettingsPresent($ctx))) {
            return;
        }
        $mode = $ctx->get('xdebug.mode');
        $discover = $ctx->get('xdebug.discover_client_host');
        $modes = array_map('trim', explode(',', strtolower($mode->text())));
        if (in_array('debug', $modes, true) && $discover->asBool()) {
            yield new Hit('xdebug.mode includes debug with discover_client_host = 1', [$mode, $discover]);
        }
        $remote = $ctx->get('xdebug.remote_enable');
        $connectBack = $ctx->get('xdebug.remote_connect_back');
        if ($remote->asBool() && $connectBack->asBool()) {
            yield new Hit('xdebug.remote_enable with remote_connect_back = 1 (Xdebug 2)', [$remote, $connectBack]);
        }
    }

    private static function xdebugSettingsPresent(Context $ctx): bool
    {
        foreach ($ctx->config->explicit() as $setting) {
            if (Util::startsWith($setting->name, 'xdebug.')) {
                return true;
            }
        }
        return false;
    }
}

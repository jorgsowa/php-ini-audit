<?php

namespace PhpIniAudit\Rules\Support;

use PhpIniAudit\Confidence;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Exposure;
use PhpIniAudit\Util;

/** Exposure conditions shared by several advisories. */
final class Exposures
{
    /** php-cgi is certain for the cgi SAPI, plausible for an unknown SAPI without FPM pools. */
    public static function cgiConfidence(Context $ctx): ?int
    {
        if ($ctx->sapi === 'cgi') {
            return Confidence::HIGH;
        }
        if ($ctx->sapi === 'unknown' && !$ctx->pools) {
            return $ctx->platform === 'windows' ? Confidence::MEDIUM : Confidence::LOW;
        }
        return null;
    }

    public static function windowsCgi(Context $ctx): ?Exposure
    {
        $confidence = self::cgiConfidence($ctx);
        if ($ctx->platform === 'windows' && $confidence !== null) {
            return new Exposure('PHP runs on Windows and may be served through php-cgi', [], $confidence);
        }
        return null;
    }

    public static function windowsProcOpen(Context $ctx): ?Exposure
    {
        if ($ctx->platform === 'windows' && !isset($ctx->disabledFunctions()['proc_open'])) {
            return new Exposure('proc_open() is callable on Windows', [$ctx->get('disable_functions')]);
        }
        return null;
    }

    public static function fpm(Context $ctx): ?Exposure
    {
        return $ctx->usesFpm() ? new Exposure('PHP-FPM is in use') : null;
    }

    public static function urlFopen(Context $ctx): ?Exposure
    {
        $setting = $ctx->get('allow_url_fopen');
        return $setting->asBool() ? new Exposure('allow_url_fopen lets file functions fetch http:// URLs', [$setting])
            : null;
    }

    public static function postReading(Context $ctx): ?Exposure
    {
        $setting = $ctx->get('enable_post_data_reading');
        if ($ctx->isWeb() && $setting->asBool()) {
            return new Exposure('PHP parses multipart request bodies', [$setting]);
        }
        return null;
    }

    public static function prefixedSessionCookie(Context $ctx): ?Exposure
    {
        $setting = $ctx->get('session.name');
        if (Util::startsWith($setting->text(), '__Host-') || Util::startsWith($setting->text(), '__Secure-')) {
            return new Exposure("session.name = {$setting->text()} relies on the cookie prefix", [$setting]);
        }
        return null;
    }
}

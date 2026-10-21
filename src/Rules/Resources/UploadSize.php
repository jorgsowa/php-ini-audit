<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class UploadSize extends ConfigRule
{
    public const ID = 'RES-004';
    public const TITLE = 'Very large uploads accepted';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['upload_max_filesize', 'post_max_size'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-770';
    public const DESCRIPTION = 'Large upload limits let clients fill the temp directory and disk.';
    public const RECOMMENDATION = 'Keep upload_max_filesize to the real requirement and below post_max_size.';

    private const GIB = 1073741824;

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('upload_max_filesize');
        $size = $setting->asBytes();
        if ($size !== null && $size > self::GIB) {
            yield new Hit("{$setting->describe()} (> 1G)", [$setting]);
        }
        $post = $ctx->get('post_max_size')->asBytes();
        if ($size !== null && $size !== 0 && $post !== null && $post > 0 && $size > $post) {
            yield new Hit(
                'upload_max_filesize exceeds post_max_size; larger uploads fail silently',
                [$setting, $ctx->get('post_max_size')],
                Severity::LOW
            );
        }
    }
}

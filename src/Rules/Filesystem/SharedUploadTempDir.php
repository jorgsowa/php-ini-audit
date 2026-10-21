<?php

namespace PhpIniAudit\Rules\Filesystem;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class SharedUploadTempDir extends ConfigRule
{
    public const ID = 'FS-010';
    public const TITLE = 'Uploads stored in the shared system temp directory';
    public const SEVERITY = Severity::INFO;
    public const DIRECTIVES = ['upload_tmp_dir', 'file_uploads'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-377';
    public const DESCRIPTION = 'Without upload_tmp_dir, uploads land in the system temp directory shared with every '
        . 'other process, which eases temp-file races and LFI-via-upload techniques.';
    public const RECOMMENDATION = 'Point upload_tmp_dir at a dedicated directory owned by the PHP user, mode 0700.';

    public function check(Context $ctx): iterable
    {
        $uploads = $ctx->get('file_uploads');
        $setting = $ctx->get('upload_tmp_dir');
        if ($uploads->asBool() && $setting->text() === '') {
            yield new Hit('upload_tmp_dir is not set', [$setting]);
        }
    }
}

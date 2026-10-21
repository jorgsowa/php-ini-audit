<?php

namespace PhpIniAudit\Rules\Resources;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class MultipartBodyParts extends ConfigRule
{
    public const ID = 'RES-011';
    public const TITLE = 'Unlimited multipart body parts';
    public const SEVERITY = Severity::LOW;
    public const DIRECTIVES = ['max_multipart_body_parts', 'max_input_vars', 'max_file_uploads'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-770';
    public const DESCRIPTION = 'max_multipart_body_parts bounds multipart parsing (CVE-2023-0662); when it is -1 the '
        . 'bound is max_input_vars + max_file_uploads, so raising those raises it too.';
    public const RECOMMENDATION = 'Keep max_input_vars and max_file_uploads modest, or set max_multipart_body_parts.';
    public const REFERENCES = ['https://nvd.nist.gov/vuln/detail/CVE-2023-0662'];

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('max_multipart_body_parts');
        $explicit = $setting->asInt();
        if ($explicit > 10000) {
            yield new Hit($setting->describe(), [$setting]);
        } elseif ($explicit < 0) {
            $derived = $ctx->get('max_input_vars')->asInt() + $ctx->get('max_file_uploads')->asInt();
            if ($derived > 10000) {
                yield new Hit(
                    "effective multipart part limit is $derived",
                    [$setting, $ctx->get('max_input_vars'), $ctx->get('max_file_uploads')]
                );
            }
        }
    }
}

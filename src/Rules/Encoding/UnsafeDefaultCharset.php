<?php

namespace PhpIniAudit\Rules\Encoding;

use PhpIniAudit\Rules\ConfigRule;
use PhpIniAudit\Rules\Context;
use PhpIniAudit\Rules\Hit;
use PhpIniAudit\Rules\Sapis;
use PhpIniAudit\Severity;

final class UnsafeDefaultCharset extends ConfigRule
{
    public const ID = 'ENC-001';
    public const TITLE = 'Unsafe default character set';
    public const SEVERITY = Severity::MEDIUM;
    public const DIRECTIVES = ['default_charset'];
    public const SAPIS = Sapis::WEB;
    public const CWE = 'CWE-838';
    public const DESCRIPTION = 'Multi-byte charsets such as GBK, Big5 or Shift_JIS let a trailing byte swallow escape '
        . 'characters (addslashes/escaping bypass, SQL injection); an empty charset leaves browsers guessing (XSS).';
    public const RECOMMENDATION = 'Set default_charset = "UTF-8".';

    private const MULTIBYTE_RISK =
        '/^(gbk|gb2312|gb18030|big5(-hkscs)?|sjis|shift[_-]?jis|cp932|cp936|cp949|cp950|euc-?jp-?ms)$/i';

    public function check(Context $ctx): iterable
    {
        $setting = $ctx->get('default_charset');
        $charset = $setting->text();
        if ($charset === '') {
            yield new Hit('default_charset is empty', [$setting], Severity::LOW);
        } elseif (preg_match(self::MULTIBYTE_RISK, $charset)) {
            yield new Hit("default_charset = $charset", [$setting]);
        } elseif (!in_array(str_replace('_', '-', strtoupper($charset)), ['UTF-8', 'UTF8'], true)) {
            yield new Hit("default_charset = $charset", [$setting], Severity::LOW);
        }
    }
}

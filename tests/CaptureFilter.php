<?php

namespace PhpIniAudit\Tests;

/** Stream filter that swallows everything written to a stream and keeps it in a buffer per stream. */
final class CaptureFilter extends \php_user_filter
{
    public const NAME = 'php-ini-audit.capture';

    /** @var array<string, string> */
    public static array $buffers = [];

    /**
     * Run $callback with STDOUT and STDERR captured; returns [callback result, stdout, stderr].
     *
     * @return array{0: mixed, 1: string, 2: string}
     */
    public static function run(callable $callback): array
    {
        if (!in_array(self::NAME, stream_get_filters(), true)) {
            stream_filter_register(self::NAME, self::class);
        }
        self::$buffers = ['stdout' => '', 'stderr' => ''];
        $out = stream_filter_append(STDOUT, self::NAME, STREAM_FILTER_WRITE, 'stdout');
        $err = stream_filter_append(STDERR, self::NAME, STREAM_FILTER_WRITE, 'stderr');
        try {
            $result = $callback();
        } finally {
            stream_filter_remove($out);
            stream_filter_remove($err);
        }
        return [$result, self::$buffers['stdout'], self::$buffers['stderr']];
    }

    /**
     * @param resource $in
     * @param resource $out
     * @param int $consumed
     * @param bool $closing
     */
    public function filter($in, $out, &$consumed, $closing): int
    {
        while ($bucket = stream_bucket_make_writeable($in)) {
            self::$buffers[$this->params] .= $bucket->data;
            $consumed += $bucket->datalen;
        }
        return PSFS_PASS_ON;
    }
}

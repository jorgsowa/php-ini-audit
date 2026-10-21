<?php

namespace PhpIniAudit\Rules;

/** SAPI groups for Rule::SAPIS; "unknown" is included wherever the SAPI could not be determined. */
final class Sapis
{
    public const WEB = ['fpm', 'cgi', 'apache2', 'litespeed', 'unknown'];
    public const FASTCGI = ['fpm', 'cgi', 'litespeed', 'unknown'];
    public const FPM = ['fpm', 'unknown'];
    public const CGI = ['cgi', 'unknown'];
}

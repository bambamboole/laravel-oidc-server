<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc;

final class Issuer
{
    public static function url(): string
    {
        return rtrim(config('oidc.issuer') ?: config('app.url'), '/');
    }
}

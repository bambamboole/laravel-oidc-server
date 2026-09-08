<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server;

use Bambamboole\LaravelOidc\Server\Contracts\IssuerResolver;

final class ConfiguredIssuerResolver implements IssuerResolver
{
    public function url(): string
    {
        return rtrim((string) (config('oidc.issuer') ?: config('app.url')), '/');
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Social;

class GoogleProvider extends OidcProvider
{
    protected function issuer(): string
    {
        return 'https://accounts.google.com';
    }
}

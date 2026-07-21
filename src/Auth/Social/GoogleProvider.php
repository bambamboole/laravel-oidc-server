<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Social;

class GoogleProvider extends OidcProvider
{
    protected function issuer(): string
    {
        return 'https://accounts.google.com';
    }
}

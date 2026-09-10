<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Providers;

class GoogleProvider extends GenericOidcProvider
{
    protected function issuer(): string
    {
        return 'https://accounts.google.com';
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Pipeline;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Illuminate\Contracts\Auth\Authenticatable;

final readonly class PersonalAccessTokenEvent
{
    /** @param list<string> $scopes */
    public function __construct(
        public Authenticatable $user,
        public Client $client,
        public array $scopes,
    ) {}
}

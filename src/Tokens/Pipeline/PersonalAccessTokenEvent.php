<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Pipeline;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Illuminate\Contracts\Auth\Authenticatable;

final readonly class PersonalAccessTokenEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $context  What the host passed to createToken(); stored with the token
     */
    public function __construct(
        public Authenticatable $user,
        public Client $client,
        public array $scopes,
        public array $context = [],
    ) {}
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Pipeline;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Illuminate\Contracts\Auth\Authenticatable;

final readonly class TokenExchangeEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $subjectClaims
     */
    public function __construct(
        public Authenticatable $user,
        public Client $client,
        public array $scopes,
        public string $audience,
        public array $subjectClaims,
    ) {}
}

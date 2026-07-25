<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Views;

use Bambamboole\LaravelOidc\Scopes\Scope;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client;

final readonly class ConsentPrompt
{
    /**
     * @param  array<int, Scope>  $scopes
     */
    public function __construct(
        public Client $client,
        public Authenticatable $user,
        public array $scopes,
        public string $authToken,
    ) {}
}

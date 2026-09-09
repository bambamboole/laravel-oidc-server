<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Views;

use Bambamboole\LaravelOidc\Server\Models\Client;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Illuminate\Contracts\Auth\Authenticatable;

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

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Views;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Illuminate\Contracts\Auth\Authenticatable;

final readonly class ConsentPrompt
{
    /**
     * @param  array<int, Scope>  $scopes
     * @param  list<string>  $resources  the resource identifiers the scopes are asked for; the realm's own issuer
     *                                   when the client named none. A scope means what the resource declaring it
     *                                   says it means, so a screen that hides this hides half the decision.
     */
    public function __construct(
        public Client $client,
        public Authenticatable $user,
        public array $scopes,
        public string $authToken,
        public array $resources,
    ) {}
}

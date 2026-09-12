<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Clients\Enums\TokenEndpointAuthMethod;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\AuthorizationCodeGrant;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\RefreshTokenGrant;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<Client>
 */
class ClientFactory extends Factory
{
    protected $model = Client::class;

    public function definition(): array
    {
        return [
            'realm_id' => Client::currentRealm(),
            'client_id' => (string) Str::uuid(),
            'name' => 'Test Client',
            'secret' => Str::random(40),
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::ClientSecretPost,
            'redirect_uris' => ['https://rp.test/callback'],
            'post_logout_redirect_uris' => [],
            'grant_types' => [AuthorizationCodeGrant::TYPE, RefreshTokenGrant::TYPE],
            'default_scopes' => ['openid'],
            'optional_scopes' => [],
            'allowed_exchange_audiences' => [],
        ];
    }

    public function public(): static
    {
        return $this->state([
            'secret' => null,
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::None,
        ]);
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Model-level client administration. The league-facing lookup lives in
 * {@see \Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\ClientRepository}.
 */
class ClientRepository
{
    public function find(string $clientId): ?Client
    {
        return Client::query()->inRealm()->where('client_id', $clientId)->first();
    }

    public function findActive(string $clientId): ?Client
    {
        $client = $this->find($clientId);

        return $client !== null && ! $client->revoked ? $client : null;
    }

    public function personalAccessClient(?string $provider = null): Client
    {
        $client = Client::query()
            ->inRealm()
            ->whereJsonContains('grant_types', 'personal_access')
            ->when($provider !== null, fn ($query) => $query->where('provider', $provider))
            ->orderBy('created_at')
            ->first();

        return $client ?? throw new RuntimeException(
            'Personal access client not found. Create one with `php artisan oidc:provision-client`.',
        );
    }

    /** @param  array<int, string>  $redirectUris */
    public function createAuthorizationCodeGrantClient(
        string $name,
        array $redirectUris,
        bool $confidential = true,
        ?Authenticatable $user = null,
    ): Client {
        return $this->create(
            name: $name,
            grantTypes: ['authorization_code', 'refresh_token'],
            redirectUris: $redirectUris,
            confidential: $confidential,
            user: $user,
        );
    }

    public function createPersonalAccessGrantClient(string $name, ?string $provider = null): Client
    {
        return $this->create($name, ['personal_access'], provider: $provider);
    }

    public function createClientCredentialsGrantClient(string $name): Client
    {
        return $this->create($name, ['client_credentials']);
    }

    public function regenerateSecret(Client $client): bool
    {
        $client->secret = Str::random(40);

        return $client->save();
    }

    /**
     * @param  array<int, string>  $grantTypes
     * @param  array<int, string>  $redirectUris
     */
    protected function create(
        string $name,
        array $grantTypes,
        array $redirectUris = [],
        ?string $provider = null,
        bool $confidential = true,
        ?Authenticatable $user = null,
        ?string $clientId = null,
    ): Client {
        $client = new Client;
        $client->setAttribute($client->getKeyName(), $client->newUniqueId());

        $client->forceFill([
            'realm_id' => Client::currentRealm(),
            // A generated client answers to its own key until someone gives it a
            // readable name; the two stay separate so renaming never touches tokens.
            'client_id' => $clientId ?? $client->getKey(),
            'name' => $name,
            'provider' => $provider,
            'redirect_uris' => $redirectUris,
            'post_logout_redirect_uris' => [],
            'grant_types' => $grantTypes,
            'allowed_exchange_audiences' => [],
            'revoked' => false,
            'owner_type' => $user !== null ? $user::class : null,
            'owner_id' => $user?->getAuthIdentifier(),
        ]);

        $client->secret = $confidential ? Str::random(40) : null;
        $client->save();

        return $client;
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Bambamboole\LaravelOidc\Server\Clients\Enums\TokenEndpointAuthMethod;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Client lookup and administration. `client_id` is the identifier relying
 * parties send and every artifact that leaves the process carries; the
 * primary key is what foreign keys and in-process comparisons use.
 */
class ClientRepository
{
    public function __construct(private readonly RealmResolver $realms) {}

    public function find(string $clientId): ?Client
    {
        return Client::query()->inRealm()->where('client_id', $clientId)->first();
    }

    public function findByKey(string $key): ?Client
    {
        return Client::query()->inRealm()->find($key);
    }

    public function findActive(string $clientId): ?Client
    {
        $client = $this->find($clientId);

        return $client instanceof Client && ! $client->revoked ? $client : null;
    }

    /**
     * @throws RuntimeException when none is configured, or the configured one is unknown or revoked
     */
    public function firstParty(FirstPartyClientConfig $config): Client
    {
        $client = $config->isConfigured() ? $this->findActive((string) $config->clientId()) : null;

        return $client ?? throw new RuntimeException('The oidc.clients.first_party.client_id is not configured or does not exist.');
    }

    public function personalAccessClient(): Client
    {
        return $this->findPersonalAccessClient() ?? throw new RuntimeException(
            'Personal access client not found. Create one with `php artisan oidc:client --personal`.',
        );
    }

    public function findPersonalAccessClient(): ?Client
    {
        return Client::query()
            ->inRealm()
            ->whereJsonContains('grant_types', 'personal_access')
            ->orderBy('created_at')
            ->first();
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

    /**
     * @param  list<string>|null  $defaultScopes  overrides the realm's default scopes
     * @param  list<string>|null  $optionalScopes  overrides the realm's optional scopes
     */
    public function createPersonalAccessGrantClient(string $name, ?array $defaultScopes = null, ?array $optionalScopes = null): Client
    {
        return $this->create($name, ['personal_access'], defaultScopes: $defaultScopes, optionalScopes: $optionalScopes);
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
     * @param  list<string>|null  $defaultScopes  overrides the realm's default scopes
     * @param  list<string>|null  $optionalScopes  overrides the realm's optional scopes
     */
    protected function create(
        string $name,
        array $grantTypes,
        array $redirectUris = [],
        bool $confidential = true,
        ?Authenticatable $user = null,
        ?string $clientId = null,
        ?array $defaultScopes = null,
        ?array $optionalScopes = null,
    ): Client {
        $settings = $this->realms->current()->clients();
        $client = new Client;
        $client->setAttribute($client->getKeyName(), $client->newUniqueId());

        $client->forceFill([
            'realm_id' => Client::currentRealm(),
            // A generated client answers to its own key until someone gives it a
            // readable name; the two stay separate so renaming never touches tokens.
            'client_id' => $clientId ?? $client->getKey(),
            'name' => $name,
            'redirect_uris' => $redirectUris,
            'post_logout_redirect_uris' => [],
            'grant_types' => $grantTypes,
            'default_scopes' => $defaultScopes ?? $settings->defaultScopes,
            'optional_scopes' => $optionalScopes ?? $settings->optionalScopes,
            'token_endpoint_auth_method' => $confidential ? TokenEndpointAuthMethod::ClientSecretPost : TokenEndpointAuthMethod::None,
            'allowed_exchange_audiences' => [],
            'revoked' => false,
            'owner_type' => $user instanceof Authenticatable ? $user::class : null,
            'owner_id' => $user?->getAuthIdentifier(),
        ]);

        $client->secret = $confidential ? Str::random(40) : null;
        $client->save();

        return $client;
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Guard;

use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\TokenRevoker;

/**
 * The access token backing the current request, attached to the authenticated
 * user by the `oidc` guard.
 */
final class CurrentAccessToken
{
    private ?string $clientId = null;

    public function __construct(public readonly AccessToken $token) {}

    public function id(): string
    {
        return $this->token->getKey();
    }

    /** @return list<string> */
    public function scopes(): array
    {
        return array_values($this->token->scopes ?? []);
    }

    /**
     * The context a personal access token was created with; empty for every other grant.
     *
     * @return array<string, mixed>
     */
    public function context(): array
    {
        return $this->token->context ?? [];
    }

    /** The wire client_id, not the primary key. */
    public function clientId(): ?string
    {
        return $this->clientId ??= $this->token->client?->client_id;
    }

    public function can(string $scope): bool
    {
        return in_array('*', $this->scopes(), true) || in_array($scope, $this->scopes(), true);
    }

    public function revoke(): bool
    {
        return app(TokenRevoker::class)->revoke($this->id());
    }
}

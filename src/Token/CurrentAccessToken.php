<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Bambamboole\LaravelOidc\Server\Models\Token;

/**
 * The access token backing the current request, attached to the authenticated
 * user by the `oidc` guard.
 */
final class CurrentAccessToken
{
    private ?string $clientId = null;

    public function __construct(public readonly Token $token) {}

    public function id(): string
    {
        return $this->token->getKey();
    }

    /** @return list<string> */
    public function scopes(): array
    {
        return array_values($this->token->scopes ?? []);
    }

    /** The wire client_id, resolved from the token's client. */
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
        return (bool) Token::query()->whereKey($this->id())->update(['revoked' => true]);
    }
}

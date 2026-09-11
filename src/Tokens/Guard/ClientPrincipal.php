<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Guard;

use BadMethodCallException;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Tokens\Contracts\AccessTokenBearer;
use Bambamboole\LaravelOidc\Server\Tokens\Contracts\OAuthenticatable;
use Bambamboole\LaravelOidc\Server\Tokens\Http\Middleware\CheckAudience;
use Bambamboole\LaravelOidc\Server\Tokens\Http\Middleware\CheckScopes;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The principal behind a userless access token — what `client_credentials` issues, and what a token
 * exchange without a subject produces: the client acting for itself. There is no user behind it, so
 * a route authorizes it by scope ({@see CheckScopes}) and audience ({@see CheckAudience}) alone;
 * nothing here carries roles or permissions.
 *
 * `$request->user() instanceof ClientPrincipal` is the test that tells a machine caller from a human
 * one, whose principal is the host application's {@see OAuthenticatable} user.
 */
final class ClientPrincipal implements AccessTokenBearer, Authenticatable
{
    private ?CurrentAccessToken $accessToken = null;

    public function __construct(public readonly Client $client) {}

    /** The wire client_id, which the token carries as both `client_id` and `sub`. */
    public function clientId(): string
    {
        return $this->client->client_id;
    }

    public function currentAccessToken(): ?CurrentAccessToken
    {
        return $this->accessToken;
    }

    public function withAccessToken(?CurrentAccessToken $accessToken): static
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    public function tokenCan(string $scope): bool
    {
        return $this->accessToken?->can($scope) ?? false;
    }

    public function getAuthIdentifierName(): string
    {
        return 'client_id';
    }

    public function getAuthIdentifier(): string
    {
        return $this->clientId();
    }

    public function getAuthPasswordName(): string
    {
        throw $this->hasNoCredentials();
    }

    public function getAuthPassword(): string
    {
        throw $this->hasNoCredentials();
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    public function setRememberToken(mixed $value): void {}

    public function getRememberTokenName(): string
    {
        return '';
    }

    /**
     * A client principal exists only for the lifetime of a request already authenticated by its
     * bearer token; the credential members of Authenticatable have no counterpart on it, and
     * reaching for one means a password or session flow was handed a machine caller.
     */
    private function hasNoCredentials(): BadMethodCallException
    {
        return new BadMethodCallException('A client principal authenticates by access token and has no password.');
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Concerns;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\CurrentAccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\PersonalAccess\PersonalAccessTokenIssuer;
use Bambamboole\LaravelOidc\Server\Tokens\PersonalAccess\PersonalAccessTokenResult;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;

trait HasAccessTokens
{
    protected ?CurrentAccessToken $oidcAccessToken = null;

    /** @return HasMany<AccessToken, $this> */
    public function tokens(): HasMany
    {
        return $this->hasMany(AccessToken::class, 'user_id', $this->getAuthIdentifierName());
    }

    /** @return MorphMany<Client, $this> */
    public function oauthApps(): MorphMany
    {
        return $this->morphMany(Client::class, 'owner');
    }

    public function currentAccessToken(): ?CurrentAccessToken
    {
        return $this->oidcAccessToken;
    }

    public function withAccessToken(?CurrentAccessToken $accessToken): static
    {
        $this->oidcAccessToken = $accessToken;

        return $this;
    }

    public function tokenCan(string $scope): bool
    {
        return $this->oidcAccessToken !== null && $this->oidcAccessToken->can($scope);
    }

    /** @param  list<string>  $scopes */
    public function createToken(string $name, array $scopes = []): PersonalAccessTokenResult
    {
        return app(PersonalAccessTokenIssuer::class)->make($this, $name, $scopes);
    }
}

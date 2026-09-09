<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\User\Concerns;

use Bambamboole\LaravelOidc\Server\Models\Client;
use Bambamboole\LaravelOidc\Server\Models\Token;
use Bambamboole\LaravelOidc\Server\PersonalAccess\PersonalAccessTokenFactory;
use Bambamboole\LaravelOidc\Server\PersonalAccess\PersonalAccessTokenResult;
use Bambamboole\LaravelOidc\Server\Token\CurrentAccessToken;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;

trait HasOidcTokens
{
    protected ?CurrentAccessToken $oidcAccessToken = null;

    /** @return HasMany<Token, $this> */
    public function tokens(): HasMany
    {
        return $this->hasMany(Token::class, 'user_id', $this->getAuthIdentifierName());
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
        return app(PersonalAccessTokenFactory::class)->make($this, $name, $scopes);
    }
}

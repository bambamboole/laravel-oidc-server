<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\User;

use Bambamboole\LaravelOidc\Server\PersonalAccess\PersonalAccessTokenResult;
use Bambamboole\LaravelOidc\Server\Token\CurrentAccessToken;
use Bambamboole\LaravelOidc\Server\Token\Token;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\HasMany;

interface OAuthenticatable extends Authenticatable
{
    public function currentAccessToken(): ?CurrentAccessToken;

    public function withAccessToken(?CurrentAccessToken $accessToken): static;

    /** @return HasMany<Token, *> */
    public function tokens(): HasMany;

    /** @param  list<string>  $scopes */
    public function createToken(string $name, array $scopes = []): PersonalAccessTokenResult;
}

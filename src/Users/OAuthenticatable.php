<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Users;

use Bambamboole\LaravelOidc\Server\Tokens\Guard\AccessTokenBearer;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Bambamboole\LaravelOidc\Server\Tokens\PersonalAccess\PersonalAccessTokenResult;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\HasMany;

interface OAuthenticatable extends AccessTokenBearer, Authenticatable
{
    /** @return HasMany<Token, *> */
    public function tokens(): HasMany;

    /** @param  list<string>  $scopes */
    public function createToken(string $name, array $scopes = []): PersonalAccessTokenResult;
}

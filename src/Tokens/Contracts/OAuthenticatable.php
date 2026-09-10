<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Contracts;

use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\PersonalAccess\PersonalAccessTokenResult;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\HasMany;

interface OAuthenticatable extends AccessTokenBearer, Authenticatable
{
    /** @return HasMany<AccessToken, *> */
    public function tokens(): HasMany;

    /** @param  list<string>  $scopes */
    public function createToken(string $name, array $scopes = []): PersonalAccessTokenResult;
}

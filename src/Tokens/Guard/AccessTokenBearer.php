<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Guard;

/**
 * A user the `oidc` guard can attach the request's access token to. The
 * Users domain widens this into OAuthenticatable for host applications.
 */
interface AccessTokenBearer
{
    public function currentAccessToken(): ?CurrentAccessToken;

    public function withAccessToken(?CurrentAccessToken $accessToken): static;
}

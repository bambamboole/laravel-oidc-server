<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\PersonalAccess;

use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;

final readonly class PersonalAccessTokenResult
{
    public function __construct(
        /** The serialized JWT; the only moment it exists in plain form. */
        public string $accessToken,
        public AccessToken $token,
    ) {}
}

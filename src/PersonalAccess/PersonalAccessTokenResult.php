<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\PersonalAccess;

use Bambamboole\LaravelOidc\Server\Models\Token;

final readonly class PersonalAccessTokenResult
{
    public function __construct(
        /** The serialized JWT; the only moment it exists in plain form. */
        public string $accessToken,
        public Token $token,
    ) {}
}

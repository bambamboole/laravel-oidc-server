<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Pipeline;

use Illuminate\Contracts\Auth\Authenticatable;
use League\OAuth2\Server\Entities\ClientEntityInterface;

/**
 * Fires for interactive access tokens: on initial authorization_code issuance
 * and again for every refresh_token reissue, so trigger claims survive token
 * rotation. `grantType` tells the two apart.
 */
final readonly class AuthorizationCodeEvent
{
    /** @param list<string> $scopes */
    public function __construct(
        public Authenticatable $user,
        public ClientEntityInterface $client,
        public array $scopes,
        public string $grantType,
    ) {}
}

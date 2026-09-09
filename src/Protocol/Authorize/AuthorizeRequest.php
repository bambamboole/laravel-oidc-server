<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Authorize;

/**
 * A validated OAuth 2.1 §4.1.1 / OpenID Connect Core §3.1.2.1 authorization
 * request. Scalar only, so it survives the consent round trip in the session.
 */
final class AuthorizeRequest
{
    /**
     * @param  string  $clientId  the wire client_id
     * @param  string  $redirectUri  the URI the response goes to, resolved against the registration
     * @param  bool  $redirectUriRequested  whether the client sent one; if so the token request must repeat it
     * @param  list<string>  $scopes
     */
    public function __construct(
        public readonly string $clientId,
        public readonly string $redirectUri,
        public readonly bool $redirectUriRequested,
        public readonly array $scopes,
        public readonly ?string $state,
        public readonly string $codeChallenge,
        public readonly string $codeChallengeMethod,
        public readonly ?string $nonce,
        public ?string $userId = null,
    ) {}
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

/**
 * Everything an id_token is built from, expressed as values: the subject
 * and client, the granted scopes, the serialized access token the at_hash
 * binds to, and the login-time facts the authentication context recorded.
 */
final readonly class IdTokenRequest
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $amr
     * @param  array<string, mixed>  $idTokenClaims
     */
    public function __construct(
        public string $userId,
        public string $clientId,
        public array $scopes,
        public string $accessToken,
        public ?string $nonce = null,
        public ?int $authTime = null,
        public array $amr = [],
        public array $idTokenClaims = [],
        public ?string $sid = null,
    ) {}
}

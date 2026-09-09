<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Exchange;

use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\AccessTokenEntity;

final readonly class IssuedToken
{
    /** @param string[] $scopes */
    public function __construct(
        public string $accessToken,
        public string $tokenType,
        public int $expiresIn,
        public string $audience,
        public array $scopes,
    ) {}

    public static function fromEntity(AccessTokenEntity $token, string $audience): self
    {
        return new self(
            accessToken: $token->toString(),
            tokenType: 'Bearer',
            expiresIn: max(0, $token->getExpiryDateTime()->getTimestamp() - time()),
            audience: $audience,
            scopes: $token->scopeIdentifiers(),
        );
    }
}

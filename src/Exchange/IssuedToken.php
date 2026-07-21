<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Exchange;

use Bambamboole\LaravelOidc\Token\OidcAccessToken;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

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

    public static function fromEntity(OidcAccessToken $token, string $audience): self
    {
        $scopes = array_map(
            fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $token->getScopes(),
        );

        return new self(
            accessToken: $token->toString(),
            tokenType: 'Bearer',
            expiresIn: max(0, $token->getExpiryDateTime()->getTimestamp() - time()),
            audience: $audience,
            scopes: array_values($scopes),
        );
    }
}

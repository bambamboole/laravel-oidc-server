<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Tokens;

use DateTimeImmutable;

final readonly class MintedAccessToken
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $audience
     */
    public function __construct(
        public string $jwt,
        public string $jti,
        public ?string $userId,
        public string $clientId,
        public array $scopes,
        public array $audience,
        public DateTimeImmutable $expiresAt,
    ) {}

    public function toString(): string
    {
        return $this->jwt;
    }
}

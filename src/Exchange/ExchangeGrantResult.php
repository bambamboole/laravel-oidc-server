<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Exchange;

final readonly class ExchangeGrantResult
{
    /**
     * @param  string[]  $scopes
     * @param  string[]  $audience
     * @param  array<string, mixed>  $context  seeded into the token_exchange pipeline's AccessTokenApi
     */
    public function __construct(
        public string $userId,
        public array $scopes,
        public array $audience,
        public int $expiresAt,
        public array $context = [],
    ) {}
}

<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Exchange;

final readonly class ExchangeGrantResult
{
    /**
     * @param  string[]  $scopes
     * @param  string[]  $audience
     */
    public function __construct(
        public string $userId,
        public array $scopes,
        public array $audience,
        public int $expiresAt,
    ) {}
}

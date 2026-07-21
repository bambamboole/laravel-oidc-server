<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Exchange;

use Laravel\Passport\Client;

final readonly class ExchangeRequest
{
    /**
     * @param  array<string, mixed>  $subjectClaims
     * @param  string[]|null  $requestedScopes
     */
    public function __construct(
        public Client $client,
        public array $subjectClaims,
        public ?string $requestedAudience,
        public ?array $requestedScopes,
        public int $subjectExpiresAt,
    ) {}
}

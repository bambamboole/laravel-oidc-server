<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Clients;

final readonly class FirstPartyClientConfig
{
    /** @param string[] $additionalTrustedClientIds */
    private function __construct(
        private ?string $resolvedClientId,
        private bool $firstPartyTrusted,
        private array $additionalTrustedClientIds,
    ) {}

    public static function fromConfig(): self
    {
        $clientId = config('oidc.first_party.client_id');
        $resolved = is_string($clientId) && $clientId !== '' ? $clientId : null;
        $trusted = array_values(array_unique(array_map(
            strval(...),
            (array) config('oidc.trusted_clients', []),
        )));

        return new self(
            resolvedClientId: $resolved,
            firstPartyTrusted: (bool) config('oidc.first_party.trusted', false),
            additionalTrustedClientIds: $trusted,
        );
    }

    public function clientId(): ?string
    {
        return $this->resolvedClientId;
    }

    public function isConfigured(): bool
    {
        return $this->resolvedClientId !== null;
    }

    public function isTrusted(string|int $clientId): bool
    {
        $clientId = (string) $clientId;

        if ($this->resolvedClientId === $clientId) {
            return $this->firstPartyTrusted;
        }

        return in_array($clientId, $this->additionalTrustedClientIds, true);
    }
}

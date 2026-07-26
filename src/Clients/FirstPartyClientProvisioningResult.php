<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Laravel\Passport\Client;

final readonly class FirstPartyClientProvisioningResult
{
    public function __construct(
        public Client $client,
        public string $clientId,
        public ?string $clientSecret,
        public bool $wasCreated,
        public bool $secretRotated,
    ) {}

    /**
     * Delete the client when it was freshly created by this provisioning call.
     * Adopted or reconciled clients are left untouched.
     */
    public function rollback(): bool
    {
        if (! $this->wasCreated) {
            return false;
        }

        return (bool) $this->client->delete();
    }

    /**
     * @return array{OIDC_FIRST_PARTY_CLIENT: string, OIDC_FIRST_PARTY_TRUSTED: string}
     */
    public function providerEnvVariables(bool $trusted = false): array
    {
        return [
            'OIDC_FIRST_PARTY_CLIENT' => $this->clientId,
            'OIDC_FIRST_PARTY_TRUSTED' => $trusted ? 'true' : 'false',
        ];
    }
}

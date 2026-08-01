<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

interface SigningKeyStore
{
    public function privateKey(): string;

    public function publicKey(): string;

    /** @return list<string> Retired public keys still valid for verification/JWKS */
    public function previousPublicKeys(): array;

    /**
     * Persist a new keypair, rolling the current public key into the previous set.
     *
     * @throws \RuntimeException when the backend cannot persist the keys
     */
    public function rotate(GeneratedSigningKeys $keys): void;
}

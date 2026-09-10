<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Keys;

use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyPair;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyStore;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

final class StoredSigningKeys implements SigningKeys
{
    public function __construct(private readonly SigningKeyStore $store) {}

    public function signingKey(): SigningKeyPair
    {
        return $this->store->signingKey();
    }

    /** @return non-empty-list<SigningKeyPair> */
    public function verificationKeys(): array
    {
        return $this->store->verificationKeys();
    }

    public function signingKid(): string
    {
        return $this->signingKey()->kid();
    }

    public function signingConfiguration(): Configuration
    {
        $key = $this->signingKey();

        return Configuration::forAsymmetricSigner(
            new Sha256,
            InMemory::plainText($key->privateKey()),
            InMemory::plainText($key->publicKeyPem),
        );
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

final class SigningKeys
{
    public function __construct(private readonly SigningKeyStore $store) {}

    public function signingKey(): SigningKey
    {
        return $this->store->signingKey();
    }

    /** @return non-empty-list<SigningKey> */
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

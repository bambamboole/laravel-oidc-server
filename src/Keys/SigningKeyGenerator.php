<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Keys;

use Bambamboole\LaravelOidc\Server\Realms\RealmResolver;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use Throwable;

final class SigningKeyGenerator
{
    public function __construct(
        private readonly SigningKeyStore $store,
        private readonly RealmResolver $realms,
    ) {}

    public function generate(): GeneratedSigningKeys
    {
        /** @var PrivateKey $key */
        $key = RSA::createKey($this->realms->current()->keys()->keySize);

        $privatePem = (string) $key;
        $publicPem = (string) $key->getPublicKey();

        return new GeneratedSigningKeys(
            privateKeyPem: $privatePem,
            publicKeyPem: $publicPem,
            kid: Jwk::fromPem($publicPem)['kid'],
        );
    }

    public function hasKeys(): bool
    {
        try {
            $this->store->signingKey();

            return true;
        } catch (Throwable) {
            return false;
        }
    }
}

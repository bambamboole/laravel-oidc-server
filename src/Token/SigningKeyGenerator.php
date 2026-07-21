<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Token;

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use Throwable;

final class SigningKeyGenerator
{
    public function generate(): GeneratedSigningKeys
    {
        /** @var PrivateKey $key */
        $key = RSA::createKey((int) config('oidc.key_size', 2048));

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
            SigningKeys::publicKey();

            return true;
        } catch (Throwable) {
            return false;
        }
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

final class SigningKeys
{
    /** @var array<string, string> */
    private static array $kidCache = [];

    public static function publicKey(): string
    {
        return app(SigningKeyStore::class)->publicKey();
    }

    /**
     * All public keys signatures may verify against: the current key plus any
     * retained previous keys from the bound store. Verification and JWKS must
     * use the same set, or rotation invalidates live tokens that relying
     * parties still consider valid.
     *
     * @return non-empty-list<string>
     */
    public static function verificationKeys(): array
    {
        $store = app(SigningKeyStore::class);

        return [$store->publicKey(), ...$store->previousPublicKeys()];
    }

    public static function privateKey(): string
    {
        return app(SigningKeyStore::class)->privateKey();
    }

    public static function signingConfiguration(): Configuration
    {
        return Configuration::forAsymmetricSigner(
            new Sha256,
            InMemory::plainText(self::privateKey()),
            InMemory::plainText(self::publicKey()),
        );
    }

    public static function signingKid(): string
    {
        $publicKey = self::publicKey();

        return self::$kidCache[$publicKey] ??= Jwk::fromPem($publicKey)['kid'];
    }
}

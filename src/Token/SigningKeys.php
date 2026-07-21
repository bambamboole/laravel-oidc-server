<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Token;

use Laravel\Passport\Passport;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use RuntimeException;

final class SigningKeys
{
    /** @var array<string, string> */
    private static array $kidCache = [];

    public static function publicKey(): string
    {
        return self::key('public');
    }

    public static function privateKey(): string
    {
        return self::key('private');
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

    private static function key(string $type): string
    {
        foreach (["oidc.{$type}_key", "passport.{$type}_key"] as $configKey) {
            $key = str_replace('\n', "\n", (string) config($configKey));

            if ($key !== '') {
                return $key;
            }
        }

        $path = Passport::keyPath("oauth-{$type}.key");
        $contents = is_readable($path) ? file_get_contents($path) : false;

        if ($contents === false) {
            throw new RuntimeException(
                "Unable to read the OIDC {$type} signing key from [{$path}]. Run `php artisan oidc:rotate-keys` or set OIDC_".strtoupper($type).'_KEY.',
            );
        }

        return $contents;
    }
}

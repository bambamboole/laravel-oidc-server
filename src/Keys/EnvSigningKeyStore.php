<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Keys;

use Bambamboole\LaravelOidc\Server\Installation\EnvironmentFile;
use RuntimeException;
use Throwable;

final class EnvSigningKeyStore implements SigningKeyStore
{
    public function __construct(private readonly EnvironmentFile $environment) {}

    public function signingKey(): SigningKey
    {
        $privateKey = $this->key('private');

        return new SigningKey($this->key('public'), $privateKey);
    }

    /** @return non-empty-list<SigningKey> */
    public function verificationKeys(): array
    {
        return [
            new SigningKey($this->key('public')),
            ...array_map(
                static fn (string $pem): SigningKey => new SigningKey($pem),
                $this->retainedPublicKeys(),
            ),
        ];
    }

    public function rotate(GeneratedSigningKeys $keys): void
    {
        $vars = [
            'OIDC_PRIVATE_KEY' => $keys->privateKeyPem,
            'OIDC_PUBLIC_KEY' => $keys->publicKeyPem,
        ];

        try {
            $vars['OIDC_PREVIOUS_PUBLIC_KEY'] = $this->key('public');
        } catch (Throwable) {
            // First-time generation: no current key to retain.
        }

        $this->environment->write($vars, EnvironmentFile::encode(...));
    }

    /** @return list<string> */
    private function retainedPublicKeys(): array
    {
        $additional = config('oidc.additional_public_keys', []);

        return array_values(array_filter(
            is_array($additional) ? $additional : [],
            fn ($key) => is_string($key) && $key !== '',
        ));
    }

    private function key(string $type): string
    {
        $key = str_replace('\n', "\n", (string) config("oidc.{$type}_key"));

        if ($key !== '') {
            return $key;
        }

        $path = rtrim((string) (config('oidc.keys.path') ?: storage_path()), '/')."/oauth-{$type}.key";
        $contents = is_readable($path) ? file_get_contents($path) : false;

        if ($contents === false) {
            throw new RuntimeException(
                "Unable to read the OIDC {$type} signing key from [{$path}]. Run `php artisan oidc:rotate-keys` or set OIDC_".strtoupper($type).'_KEY.',
            );
        }

        return $contents;
    }
}

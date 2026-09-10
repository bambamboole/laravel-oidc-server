<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Keys;

use Bambamboole\LaravelOidc\Server\Shared\Installation\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Shared\Keys\GeneratedSigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyPair;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyStore;
use RuntimeException;
use Throwable;

final readonly class EnvSigningKeyStore implements SigningKeyStore
{
    public function __construct(private EnvironmentFile $environment) {}

    public function signingKey(): SigningKeyPair
    {
        $privateKey = $this->key('private');

        return new SigningKeyPair($this->key('public'), $privateKey);
    }

    /** @return non-empty-list<SigningKeyPair> */
    public function verificationKeys(): array
    {
        return [
            new SigningKeyPair($this->key('public')),
            ...array_map(
                static fn (string $pem): SigningKeyPair => new SigningKeyPair($pem),
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
        $additional = config('oidc.keys.additional_public_keys', []);

        return array_values(array_filter(
            is_array($additional) ? $additional : [],
            fn ($key): bool => is_string($key) && $key !== '',
        ));
    }

    private function key(string $type): string
    {
        $key = str_replace('\n', "\n", (string) config("oidc.keys.{$type}_key"));

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

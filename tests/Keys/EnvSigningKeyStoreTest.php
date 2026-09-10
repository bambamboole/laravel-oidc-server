<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Keys\EnvSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Shared\Installation\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Shared\Keys\GeneratedSigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyPair;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyStore;

/**
 * @return array{0: EnvSigningKeyStore, 1: string}
 */
function envStoreFixture(): array
{
    $path = temporaryTestDirectory('env-store').'/.env';
    file_put_contents($path, "APP_NAME=Testing\n");

    return [new EnvSigningKeyStore(new EnvironmentFile($path)), $path];
}

it('filters non-string and empty entries out of retained public keys', function () {
    config(['oidc.keys.additional_public_keys' => ['valid-key', '', 42, null]]);

    [$store] = envStoreFixture();

    expect(array_map(
        fn (SigningKeyPair $key): string => $key->publicKeyPem,
        array_slice($store->verificationKeys(), 1),
    ))->toBe(['valid-key']);
});

it('rotates by writing the new keypair and rolling the current public key', function () {
    [$store, $path] = envStoreFixture();
    $current = $store->signingKey()->publicKeyPem;

    $store->rotate(new GeneratedSigningKeys(
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\r\nnew-private\r\n-----END PRIVATE KEY-----\r\n",
        publicKeyPem: "-----BEGIN PUBLIC KEY-----\r\nnew-public\r\n-----END PUBLIC KEY-----\r\n",
        kid: 'new-kid',
    ));

    $reader = new EnvironmentFile($path);

    expect((string) file_get_contents($path))->not->toContain("\r")
        ->and($reader->value('OIDC_PRIVATE_KEY'))
        ->toBe("-----BEGIN PRIVATE KEY-----\nnew-private\n-----END PRIVATE KEY-----")
        ->and($reader->value('OIDC_PUBLIC_KEY'))
        ->toBe("-----BEGIN PUBLIC KEY-----\nnew-public\n-----END PUBLIC KEY-----")
        ->and($reader->value('OIDC_PREVIOUS_PUBLIC_KEY'))->toBe(trim($current));
});

it('omits the previous key when no current key exists', function () {
    config(['oidc.keys.public_key' => null]);
    config(['oidc.keys.path' => temporaryTestDirectory('env-store-nokeys')]);

    [$store, $path] = envStoreFixture();

    $store->rotate(new GeneratedSigningKeys(
        privateKeyPem: "private\n",
        publicKeyPem: "public\n",
        kid: 'first-kid',
    ));

    expect((string) file_get_contents($path))->not->toContain('OIDC_PREVIOUS_PUBLIC_KEY=');
});

it('binds the env store as the configured SigningKeyStore', function () {
    $first = app(SigningKeyStore::class);

    expect($first::class)->toBe(EnvSigningKeyStore::class)
        ->and($first)->toBe(app(SigningKeyStore::class));
});

<?php

declare(strict_types=1);

/**
 * Database-backed signing keys: rotation retains the previous key for verification (RFC 7517 §5 key set), private keys encrypted at rest
 */

use Bambamboole\LaravelOidc\Server\Keys\DatabaseSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Keys\Models\SigningKey;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyGenerator;
use Bambamboole\LaravelOidc\Server\Keys\StoredSigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyPair;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Illuminate\Support\Facades\DB;

/**
 * The store binding is a singleton read once at first resolution, so swapping it
 * mid-test has to replace the service that holds it as well.
 */
function useDatabaseSigningKeys(): DatabaseSigningKeyStore
{
    $store = new DatabaseSigningKeyStore;

    app()->instance(SigningKeyStore::class, $store);
    app()->instance(SigningKeys::class, new StoredSigningKeys($store));

    return $store;
}

function databaseStoreRotate(): SigningKeyPair
{
    $store = useDatabaseSigningKeys();
    $generated = (new SigningKeyGenerator($store, app(RealmResolver::class)))->generate();
    $store->rotate($generated);

    return new SigningKeyPair($generated->publicKeyPem, $generated->privateKeyPem, $generated->kid);
}

it('fails loud when no key has been generated yet', function () {
    useDatabaseSigningKeys()->signingKey();
})->throws(RuntimeException::class, 'oidc:rotate-keys');

it('signs with the key stored by the last rotation', function () {
    $generated = databaseStoreRotate();

    $key = useDatabaseSigningKeys()->signingKey();

    expect($key->kid())->toBe($generated->kid())
        ->and($key->publicKeyPem)->toBe($generated->publicKeyPem)
        ->and($key->privateKey())->toBe($generated->privateKeyPem);
});

it('retires the previous key but keeps it for verification', function () {
    $first = databaseStoreRotate();
    $second = databaseStoreRotate();

    $keys = useDatabaseSigningKeys()->verificationKeys();

    expect(useDatabaseSigningKeys()->signingKey()->kid())->toBe($second->kid())
        ->and(array_map(fn (SigningKeyPair $key): string => $key->kid(), $keys))
        ->toBe([$second->kid(), $first->kid()]);
});

it('stores the private key encrypted at rest', function () {
    $generated = databaseStoreRotate();

    $raw = DB::table('oidc_signing_keys')->where('kid', $generated->kid())->value('private_key');

    expect($raw)->not->toContain('PRIVATE KEY')
        ->and(SigningKey::query()->where('kid', $generated->kid())->sole()->private_key)
        ->toBe($generated->privateKeyPem);
});

it('serves every retained kid from the jwks endpoint', function () {
    $first = databaseStoreRotate();
    $second = databaseStoreRotate();

    $response = $this->getJson('/realms/default/.well-known/jwks.json')->assertOk();

    expect(array_column($response->json('keys'), 'kid'))->toBe([$second->kid(), $first->kid()]);
});

it('keeps tokens signed before a rotation verifiable', function () {
    databaseStoreRotate();
    $beforeRotation = app(SigningKeys::class)->signingConfiguration();
    $kidBefore = app(SigningKeys::class)->signingKid();

    $jwt = $beforeRotation->builder()
        ->withHeader('kid', $kidBefore)
        ->issuedBy(app(IssuerResolver::class)->url())
        ->identifiedBy('token-id')
        ->getToken($beforeRotation->signer(), $beforeRotation->signingKey())
        ->toString();

    databaseStoreRotate();

    expect(app(SigningKeys::class)->signingKid())->not->toBe($kidBefore)
        ->and(app(TokenInspector::class)->parse($jwt))->not->toBeNull();
});

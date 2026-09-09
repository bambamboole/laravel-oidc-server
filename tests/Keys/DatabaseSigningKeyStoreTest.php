<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Keys\DatabaseSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Keys\Jwk;
use Bambamboole\LaravelOidc\Server\Keys\SigningKey;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyGenerator;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyRecord;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyStore;
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
    app()->instance(SigningKeys::class, new SigningKeys($store));

    return $store;
}

function databaseStoreRotate(): SigningKey
{
    $store = useDatabaseSigningKeys();
    $generated = (new SigningKeyGenerator($store))->generate();
    $store->rotate($generated);

    return new SigningKey($generated->publicKeyPem, $generated->privateKeyPem, $generated->kid);
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
        ->and(array_map(fn (SigningKey $key): string => $key->kid(), $keys))
        ->toBe([$second->kid(), $first->kid()]);
});

it('stores the private key encrypted at rest', function () {
    $generated = databaseStoreRotate();

    $raw = DB::table('oidc_signing_keys')->where('kid', $generated->kid())->value('private_key');

    expect($raw)->not->toContain('PRIVATE KEY')
        ->and(SigningKeyRecord::query()->where('kid', $generated->kid())->sole()->private_key)
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
        ->issuedBy('https://op.test')
        ->identifiedBy('token-id')
        ->getToken($beforeRotation->signer(), $beforeRotation->signingKey())
        ->toString();

    databaseStoreRotate();

    expect(app(SigningKeys::class)->signingKid())->not->toBe($kidBefore)
        ->and(app(TokenInspector::class)->parse($jwt))->not->toBeNull();
});

it('publishes the stored kid rather than re-deriving it', function () {
    $generated = databaseStoreRotate();

    SigningKeyRecord::query()->where('kid', $generated->kid())->update(['kid' => 'pinned-kid']);

    expect(useDatabaseSigningKeys()->signingKey()->kid())->toBe('pinned-kid')
        ->and(Jwk::fromPem($generated->publicKeyPem)['kid'])->not->toBe('pinned-kid')
        ->and($this->getJson('/realms/default/.well-known/jwks.json')->json('keys.0.kid'))->toBe('pinned-kid');
});

<?php

declare(strict_types=1);

/**
 * RFC 7517 §5 (JWK Set retained across rotation)
 */

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\SigningKeyPair;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\SigningKeys\Models\SigningKey;
use Bambamboole\LaravelOidc\Server\SigningKeys\SigningKeyGenerator;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Illuminate\Support\Facades\DB;

function useDatabaseSigningKeys(): SigningKeyStore
{
    return app(SigningKeyStore::class);
}

function databaseStoreRotate(): SigningKeyPair
{
    $store = useDatabaseSigningKeys();
    $generated = app(SigningKeyGenerator::class)->generate();
    $store->rotate($generated);

    return new SigningKeyPair($generated->publicKeyPem, $generated->privateKeyPem, $generated->kid);
}

it('fails loud when no key has been generated yet', function (): void {
    SigningKey::query()->delete();

    useDatabaseSigningKeys()->signingKey();
})->throws(RuntimeException::class, 'oidc:rotate-keys');

it('signs with the key stored by the last rotation', function (): void {
    $generated = databaseStoreRotate();

    $key = useDatabaseSigningKeys()->signingKey();

    expect($key->kid())->toBe($generated->kid())
        ->and($key->publicKeyPem)->toBe($generated->publicKeyPem)
        ->and($key->privateKey())->toBe($generated->privateKeyPem);
});

it('retires the previous key but keeps it for verification', function (): void {
    SigningKey::query()->delete();
    $first = databaseStoreRotate();
    $second = databaseStoreRotate();

    $keys = useDatabaseSigningKeys()->verificationKeys();

    expect(useDatabaseSigningKeys()->signingKey()->kid())->toBe($second->kid())
        ->and(array_map(fn (SigningKeyPair $key): string => $key->kid(), $keys))
        ->toBe([$second->kid(), $first->kid()]);
});

it('stores the private key encrypted at rest', function (): void {
    $generated = databaseStoreRotate();

    $raw = DB::table('oidc_signing_keys')->where('kid', $generated->kid())->value('private_key');

    expect($raw)->not->toContain('PRIVATE KEY')
        ->and(SigningKey::query()->where('kid', $generated->kid())->sole()->private_key)
        ->toBe($generated->privateKeyPem);
});

it('serves every retained kid from the jwks endpoint', function (): void {
    SigningKey::query()->delete();
    $first = databaseStoreRotate();
    $second = databaseStoreRotate();

    $response = $this->getJson('/.well-known/jwks.json')->assertOk();

    expect(array_column($response->json('keys'), 'kid'))->toBe([$second->kid(), $first->kid()]);
});

it('keeps tokens signed before a rotation verifiable', function (): void {
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

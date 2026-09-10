<?php

declare(strict_types=1);

/**
 * Signing key resolution: env-provided PEM (escaped newlines) over key files, failing loud when neither exists
 */
function escapedFixtureKey(string $file): string
{
    return str_replace("\n", '\n', trim((string) file_get_contents(__DIR__.'/../fixtures/'.$file)));
}

it('resolves keys from oidc config with escaped newlines', function (): void {
    config(['oidc.keys.public_key' => escapedFixtureKey('oauth-public.key')]);

    expect(signingPublicKey())
        ->toBe(trim((string) file_get_contents(__DIR__.'/../fixtures/oauth-public.key')));
});

it('falls back to key files when no config key is set', function (): void {
    config(['oidc.keys.public_key' => null]);

    expect(signingPublicKey())
        ->toBe(file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));
});

it('fails loud when neither config key nor key file exists', function (): void {
    config(['oidc.keys.private_key' => null]);
    config(['oidc.keys.path' => '/nonexistent']);

    signingPrivateKey();
})->throws(RuntimeException::class, 'OIDC_PRIVATE_KEY');

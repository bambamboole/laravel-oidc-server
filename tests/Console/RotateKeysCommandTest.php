<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Token\Jwk;
use Bambamboole\LaravelOidc\Server\Token\SigningKeys;
use Illuminate\Support\Facades\File;
use Laravel\Passport\Passport;

function rotateKeysEnv(string $contents = "APP_NAME=Testing\n"): string
{
    $directory = temporaryTestDirectory('rotate-keys');
    File::put($directory.'/.env', $contents);
    app()->useEnvironmentPath($directory);

    return $directory.'/.env';
}

function decodeEnvKey(string $envContents, string $name): string
{
    expect(preg_match('/^'.preg_quote($name, '/').'="(.*)"$/m', $envContents, $m))->toBe(1);

    return str_replace('\n', "\n", $m[1]);
}

it('writes a new keypair and the previous public key to .env', function () {
    $env = rotateKeysEnv();
    $currentKid = Jwk::fromPem(SigningKeys::publicKey())['kid'];

    $this->artisan('oidc:rotate-keys', ['--force' => true])->assertSuccessful();

    $contents = (string) file_get_contents($env);
    $newPrivate = decodeEnvKey($contents, 'OIDC_PRIVATE_KEY');
    $newPublic = decodeEnvKey($contents, 'OIDC_PUBLIC_KEY');
    $previousPublic = decodeEnvKey($contents, 'OIDC_PREVIOUS_PUBLIC_KEY');

    expect($newPrivate)->toContain('BEGIN PRIVATE KEY')
        ->and(Jwk::fromPem($newPublic)['kid'])->not->toBe($currentKid)
        ->and(Jwk::fromPem($previousPublic)['kid'])->toBe($currentKid);
});

it('upserts existing keys instead of duplicating them', function () {
    $env = rotateKeysEnv("APP_NAME=Testing\nOIDC_PRIVATE_KEY=\"stale\"\nOTHER=keep\n");

    $this->artisan('oidc:rotate-keys', ['--force' => true])->assertSuccessful();

    $contents = (string) file_get_contents($env);

    expect(substr_count($contents, 'OIDC_PRIVATE_KEY='))->toBe(1)
        ->and($contents)->toContain('OTHER=keep')
        ->and(decodeEnvKey($contents, 'OIDC_PRIVATE_KEY'))->not->toContain('stale');
});

it('prints the env variables without touching .env when --print is given', function () {
    $env = rotateKeysEnv();
    $before = (string) file_get_contents($env);

    $this->artisan('oidc:rotate-keys', ['--print' => true])
        ->expectsOutputToContain('OIDC_PRIVATE_KEY=')
        ->expectsOutputToContain('OIDC_PREVIOUS_PUBLIC_KEY=')
        ->assertSuccessful();

    expect((string) file_get_contents($env))->toBe($before);
});

it('aborts without writing when the confirmation is declined', function () {
    $env = rotateKeysEnv();
    $before = (string) file_get_contents($env);

    $this->artisan('oidc:rotate-keys')
        ->expectsConfirmation('Generate a new signing keypair and write it to .env?', 'no')
        ->assertSuccessful();

    expect((string) file_get_contents($env))->toBe($before);
});

it('omits the previous key on a first-time generation with no current key', function () {
    config(['passport.private_key' => null, 'passport.public_key' => null]);
    Passport::loadKeysFrom(temporaryTestDirectory('nokeys'));
    $env = rotateKeysEnv();

    $this->artisan('oidc:rotate-keys', ['--force' => true])->assertSuccessful();

    $contents = (string) file_get_contents($env);

    expect($contents)->toContain('OIDC_PRIVATE_KEY=')
        ->and($contents)->not->toContain('OIDC_PREVIOUS_PUBLIC_KEY=');
});

it('skips generation with --if-missing when keys already exist', function () {
    $env = rotateKeysEnv();
    $before = (string) file_get_contents($env);

    $this->artisan('oidc:rotate-keys', ['--if-missing' => true])
        ->expectsOutputToContain('already exist')
        ->assertSuccessful();

    expect((string) file_get_contents($env))->toBe($before);
});

it('generates without confirmation with --if-missing when no keys exist', function () {
    config(['passport.private_key' => null, 'passport.public_key' => null]);
    Passport::loadKeysFrom(temporaryTestDirectory('nokeys-if-missing'));
    $env = rotateKeysEnv();

    $this->artisan('oidc:rotate-keys', ['--if-missing' => true])->assertSuccessful();

    expect((string) file_get_contents($env))->toContain('OIDC_PRIVATE_KEY=');
});

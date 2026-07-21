<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Laravel\Passport\Passport;

function installSelfEnv(string $contents = "APP_NAME=Testing\n"): string
{
    $directory = sys_get_temp_dir().'/laravel-oidc-install-self-'.uniqid();
    File::makeDirectory($directory, 0755, true, true);
    File::put($directory.'/.env', $contents);
    app()->useEnvironmentPath($directory);

    return $directory.'/.env';
}

it('provisions the first-party client and writes both env halves', function () {
    $env = installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test', 'oidc.issuer' => null]);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $client = Passport::client()->newQuery()->where('oidc_provisioning_key', 'first-party')->firstOrFail();
    $clientId = (string) $client->getKey();
    $contents = (string) File::get($env);

    expect($contents)
        ->toContain('OIDC_FIRST_PARTY_CLIENT='.$clientId)
        ->toContain('OIDC_FIRST_PARTY_TRUSTED=true')
        ->toContain('OIDC_RP_ENABLED=true')
        ->toContain('OIDC_RP_ISSUER=https://app.test')
        ->toContain('OIDC_RP_CLIENT_ID='.$clientId)
        ->toContain('OIDC_RP_REDIRECT_URI=https://app.test/login/callback')
        ->toContain('OIDC_RP_POST_LOGOUT_REDIRECT_URI=https://app.test')
        ->toContain('OIDC_ISSUER=https://app.test')
        ->and(preg_match('/^OIDC_RP_CLIENT_SECRET=.+$/m', $contents))->toBe(1);
});

it('forwards configured provisioning options to the first-party client', function () {
    installSelfEnv();
    config([
        'oidc-client' => [],
        'app.url' => 'https://app.test',
        'oidc.first_party.provision' => [
            'redirect_uris' => ['https://app.test/other/callback'],
            'post_logout_redirect_uris' => ['https://app.test/goodbye'],
            'allowed_exchange_audiences' => ['https://api.test'],
        ],
    ]);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $client = Passport::client()->newQuery()->where('oidc_provisioning_key', 'first-party')->firstOrFail();

    expect($client->getAttribute('redirect_uris'))->toBe(['https://app.test/login/callback', 'https://app.test/other/callback'])
        ->and(json_decode((string) $client->getRawOriginal('post_logout_redirect_uris'), true))
        ->toBe(['https://app.test', 'https://app.test/goodbye'])
        ->and(json_decode((string) $client->getRawOriginal('allowed_exchange_audiences'), true))
        ->toBe(['https://api.test'])
        ->and($client->getAttribute('grant_types'))->toContain('urn:ietf:params:oauth:grant-type:token-exchange');
});

it('provisions without token exchange when no audiences are configured', function () {
    installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $client = Passport::client()->newQuery()->where('oidc_provisioning_key', 'first-party')->firstOrFail();

    expect(json_decode((string) $client->getRawOriginal('allowed_exchange_audiences'), true))->toBe([])
        ->and($client->getAttribute('grant_types'))->not->toContain('urn:ietf:params:oauth:grant-type:token-exchange');
});

it('adopts the existing client on a second run instead of minting a new one', function () {
    $env = installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $firstContents = (string) File::get($env);
    preg_match('/^OIDC_RP_CLIENT_SECRET=(.+)$/m', $firstContents, $secret);
    preg_match('/^OIDC_FIRST_PARTY_CLIENT=(.+)$/m', $firstContents, $clientId);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $secondContents = (string) File::get($env);

    expect(Passport::client()->newQuery()->count())->toBe(1)
        ->and($secondContents)->toContain('OIDC_FIRST_PARTY_CLIENT='.$clientId[1])
        ->and($secondContents)->toContain('OIDC_RP_CLIENT_SECRET='.$secret[1]);
});

it('rotates the client secret when run again with --fresh', function () {
    $env = installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    preg_match('/^OIDC_RP_CLIENT_SECRET=(.+)$/m', (string) File::get($env), $secret);
    $clientId = (string) Passport::client()->newQuery()->firstOrFail()->getKey();

    $this->artisan('oidc:install-self', ['--force' => true, '--fresh' => true])->assertSuccessful();

    $contents = (string) File::get($env);
    preg_match('/^OIDC_RP_CLIENT_SECRET=(.+)$/m', $contents, $rotated);

    expect(Passport::client()->newQuery()->count())->toBe(1)
        ->and($contents)->toContain('OIDC_FIRST_PARTY_CLIENT='.$clientId)
        ->and($rotated[1])->not->toBe($secret[1]);
});

it('fails instead of rotating when the configured secret no longer matches', function () {
    $env = installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    File::put($env, (string) preg_replace(
        '/^OIDC_RP_CLIENT_SECRET=.+$/m',
        'OIDC_RP_CLIENT_SECRET=tampered',
        (string) File::get($env),
    ));

    $this->artisan('oidc:install-self', ['--force' => true])->assertFailed();
});

it('fails when the relying-party package is not installed', function () {
    $env = installSelfEnv();
    $before = File::get($env);
    config(['oidc-client' => null, 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertFailed();

    expect(File::get($env))->toBe($before);
});

<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

function clientCommandEnv(string $contents = "APP_NAME=Testing\n"): string
{
    $directory = sys_get_temp_dir().'/laravel-oidc-client-command-'.uniqid();
    File::makeDirectory($directory, 0755, true, true);
    File::put($directory.'/.env', $contents);
    app()->useEnvironmentPath($directory);

    return $directory.'/.env';
}

it('creates and prints first-party credentials without changing env', function () {
    $env = clientCommandEnv();
    $before = File::get($env);

    $exitCode = Artisan::call('oidc:client', [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback', 'https://app.test/oauth/callback'],
        '--post-logout-redirect-uri' => ['https://app.test/logged-out', 'https://app.test/signed-out'],
        '--audience' => ['urn:example:orders', 'https://api.test/invoices'],
        '--no-interaction' => true,
    ]);
    $output = trim(Artisan::output());
    preg_match('/^OIDC_RP_CLIENT_SECRET=(.+)$/m', $output, $secretMatch);
    $client = Passport::client()->newQuery()->where('oidc_provisioning_key', 'first-party')->firstOrFail();
    $clientId = (string) $client->getKey();
    $plainSecret = $secretMatch[1] ?? null;

    expect($exitCode)->toBe(0)
        ->and($plainSecret)->toBeString()->not->toBeEmpty()
        ->and($output)->toBe(implode(PHP_EOL, [
            'OIDC_FIRST_PARTY_CLIENT='.$clientId,
            'OIDC_FIRST_PARTY_TRUSTED=false',
            'OIDC_RP_CLIENT_ID='.$clientId,
            'OIDC_RP_CLIENT_SECRET='.$plainSecret,
        ]))
        ->and(Hash::check($plainSecret, (string) $client->getRawOriginal('secret')))->toBeTrue()
        ->and($client->getAttribute('redirect_uris'))->toBe([
            'https://app.test/login/callback',
            'https://app.test/oauth/callback',
        ])
        ->and(json_decode((string) $client->getRawOriginal('post_logout_redirect_uris'), true, flags: JSON_THROW_ON_ERROR))->toBe([
            'https://app.test/logged-out',
            'https://app.test/signed-out',
        ])
        ->and(json_decode((string) $client->getRawOriginal('allowed_exchange_audiences'), true, flags: JSON_THROW_ON_ERROR))->toBe([
            'urn:example:orders',
            'https://api.test/invoices',
        ])
        ->and(File::get($env))->toBe($before);
});

it('reconciles without printing a secret and writes selected config explicitly', function () {
    $env = clientCommandEnv("APP_NAME=Testing\nOTHER=keep\n");
    $arguments = [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--trusted' => true,
        '--write-env' => true,
        '--no-interaction' => true,
    ];

    $this->artisan('oidc:client', $arguments)->assertSuccessful();
    $this->artisan('oidc:client', $arguments)
        ->doesntExpectOutputToContain('OIDC_RP_CLIENT_SECRET=')
        ->assertSuccessful();

    expect(File::get($env))->toContain('OIDC_FIRST_PARTY_CLIENT=')
        ->toContain('OIDC_FIRST_PARTY_TRUSTED=true')
        ->toContain('OTHER=keep');
});

it('prompts for required interactive values and confirms env writes', function () {
    $env = clientCommandEnv();

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--write-env' => true,
    ])->expectsQuestion('Client name', 'First-party app')
        ->expectsQuestion('Redirect URIs (comma separated)', 'https://app.test/login/callback')
        ->expectsConfirmation('Write OIDC_FIRST_PARTY_CLIENT and OIDC_FIRST_PARTY_TRUSTED to .env?', 'yes')
        ->assertSuccessful();

    expect(File::get($env))->toContain('OIDC_FIRST_PARTY_CLIENT=');
});

it('adopts an eligible client without printing its stored hash', function () {
    $env = clientCommandEnv();
    $client = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Legacy', ['https://legacy.test/callback']);
    $hash = (string) $client->getRawOriginal('secret');

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--adopt' => (string) $client->getKey(),
        '--no-interaction' => true,
    ])->doesntExpectOutputToContain($hash)
        ->doesntExpectOutputToContain('OIDC_RP_CLIENT_SECRET=')
        ->assertSuccessful();

    expect(File::get($env))->toBe("APP_NAME=Testing\n")
        ->and($client->refresh()->getRawOriginal('oidc_provisioning_key'))->toBe('first-party');
});

it('leaves env unchanged after a provisioning failure', function () {
    $env = clientCommandEnv();
    $before = File::get($env);

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['not-a-uri'],
        '--write-env' => true,
        '--no-interaction' => true,
    ])->assertFailed();

    expect(File::get($env))->toBe($before);
});

it('requires explicit rotation before printing a replacement secret', function () {
    $base = [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--no-interaction' => true,
    ];

    $this->artisan('oidc:client', $base)->assertSuccessful();
    $this->artisan('oidc:client', $base)
        ->doesntExpectOutputToContain('OIDC_RP_CLIENT_SECRET=')
        ->assertSuccessful();
    $this->artisan('oidc:client', [...$base, '--rotate' => true])
        ->expectsOutputToContain('OIDC_RP_CLIENT_SECRET=')
        ->assertSuccessful();
});

it('rejects calls without first-party mode', function () {
    $this->artisan('oidc:client', [
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--no-interaction' => true,
    ])->assertExitCode(2);
});

it('rejects missing required values when running non-interactively', function (array $arguments) {
    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--no-interaction' => true,
        ...$arguments,
    ])->assertExitCode(2);
})->with([
    'name' => [['--redirect-uri' => ['https://app.test/login/callback']]],
    'redirect URI' => [['--name' => 'First-party app']],
]);

it('does not write env when interactive confirmation is declined', function () {
    $env = clientCommandEnv();
    $before = File::get($env);

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--write-env' => true,
    ])->expectsConfirmation('Write OIDC_FIRST_PARTY_CLIENT and OIDC_FIRST_PARTY_TRUSTED to .env?', 'no')
        ->expectsOutput('Credentials were not written to .env.')
        ->assertSuccessful();

    expect(File::get($env))->toBe($before);
});

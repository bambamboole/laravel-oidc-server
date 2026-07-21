<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Contracts\SessionTokenProvider;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Laravel\Passport\ClientRepository;
use Workbench\App\Models\User;

it('honors first-party config mutated after the singletons were resolved', function () {
    // Both singletons must exist before the config lands for this to prove anything.
    $provider = app(SessionTokenProvider::class);
    Oidc::issuer();

    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    config(['oidc.first_party.client_id' => (string) $client->id]);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->startSession();
    $this->actingAs($user);

    $provider->establish($user);

    expect(session('oidc.session_token')['jwt'] ?? null)->toBeString();
});

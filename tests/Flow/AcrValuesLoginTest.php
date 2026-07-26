<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §3.1.2.1 (acr_values)
 */

use Bambamboole\LaravelOidc\Server\Auth\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Server\Facades\Oidc;
use Bambamboole\LaravelOidc\Server\Routing\Handler;
use Laravel\Passport\ClientRepository;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => bcrypt('secret-password')]);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    $verifier = str_repeat('v', 64);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

    $this->query = http_build_query([
        'client_id' => $this->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ]);
});

it('exposes the pending authorize request acr_values to postLogin hooks', function () {
    $captured = null;
    Oidc::postLogin(function (LoginEvent $event, LoginApi $api) use (&$captured) {
        $captured = $event;
    });

    $this->get('/oauth/authorize?'.$this->query.'&acr_values=mfa phishing-resistant')
        ->assertRedirect();

    $this->post(route(Handler::LoginStore->value), ['email' => 'm@example.com', 'password' => 'secret-password']);

    expect($captured)->toBeInstanceOf(LoginEvent::class)
        ->and($captured->requestsAcr('mfa'))->toBeTrue()
        ->and($captured->requestsAcr('phishing-resistant'))->toBeTrue()
        ->and($captured->requestedAcrValues)->toBe(['mfa', 'phishing-resistant']);
});

it('does not leak acr_values from an earlier authorize request without them', function () {
    $captured = null;
    Oidc::postLogin(function (LoginEvent $event, LoginApi $api) use (&$captured) {
        $captured = $event;
    });

    $this->get('/oauth/authorize?'.$this->query.'&acr_values=mfa')->assertRedirect();
    $this->get('/oauth/authorize?'.$this->query)->assertRedirect();

    $this->post(route(Handler::LoginStore->value), ['email' => 'm@example.com', 'password' => 'secret-password']);

    expect($captured)->toBeInstanceOf(LoginEvent::class)
        ->and($captured->requestedAcrValues)->toBe([]);
});

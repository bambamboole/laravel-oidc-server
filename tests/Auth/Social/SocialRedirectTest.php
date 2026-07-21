<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Social\PendingAuthorization;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Support\Facades\Http;

function enableCorpProvider(): void
{
    config()->set('oidc.social.providers.corp', [
        'driver' => 'oidc',
        'issuer' => 'https://idp.test',
        'client_id' => 'client-1',
        'client_secret' => 'shhh',
    ]);

    Http::fake([
        'https://idp.test/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://idp.test',
            'authorization_endpoint' => 'https://idp.test/authorize',
            'token_endpoint' => 'https://idp.test/token',
            'jwks_uri' => 'https://idp.test/jwks',
        ]),
    ]);
}

it('redirects to the upstream provider and stores the pending authorization', function () {
    enableCorpProvider();

    $response = $this->get(route(Handler::SocialRedirect->value, ['provider' => 'corp']));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://idp.test/authorize?')
        ->and(session(PendingAuthorization::SESSION_KEY)['provider'])->toBe('corp')
        ->and(session(PendingAuthorization::SESSION_KEY)['intent'])->toBe('login');
});

it('responds 404 for an unknown or credential-less provider', function () {
    $this->get(route(Handler::SocialRedirect->value, ['provider' => 'github']))->assertNotFound();
    $this->get(route(Handler::SocialRedirect->value, ['provider' => 'nope']))->assertNotFound();
});

it('bounces the form_post callback to a GET so the session cookie is available', function () {
    enableCorpProvider();

    $this->post(route(Handler::SocialCallback->value, ['provider' => 'corp']), [
        'code' => 'code-1',
        'state' => 'state-1',
        'user' => '{"name":{"firstName":"Mona"}}',
    ])->assertStatus(303)->assertRedirect(
        route(Handler::SocialCallback->value, ['provider' => 'corp'])
            .'?'.http_build_query(['code' => 'code-1', 'state' => 'state-1', 'user' => '{"name":{"firstName":"Mona"}}']),
    );
});

it('redirects to login with an error when the provider reports one', function () {
    enableCorpProvider();

    $this->get(route(Handler::SocialCallback->value, ['provider' => 'corp']).'?error=access_denied')
        ->assertRedirect(route(Handler::Login->value))
        ->assertSessionHasErrors('social');
});

it('redirects to login when no pending authorization exists', function () {
    enableCorpProvider();

    $this->get(route(Handler::SocialCallback->value, ['provider' => 'corp']).'?code=x&state=y')
        ->assertRedirect(route(Handler::Login->value))
        ->assertSessionHasErrors('social');
});

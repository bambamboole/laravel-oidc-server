<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Credentials\TotpFactorProvider;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => bcrypt('secret-password')]);
});

it('denies a login when the postLogin hook denies', function () {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertSessionHasErrors('email');

    $this->assertGuest('identity');
});

it('buffers postLogin id_token claims into the session', function () {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->setIdTokenClaim('groups', ['admin']));

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password']);

    expect(session()->get('oidc.id_token_claims'))->toBe(['groups' => ['admin']]);
});

it('buffers postLogin access_token claims into the session', function () {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->setAccessTokenClaim('tier', 'gold'));

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password']);

    expect(session()->get('oidc.access_token_claims'))->toBe(['tier' => 'gold']);
});

it('denies when requireMfa is requested but the user has no factor', function () {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertSessionHasErrors('email');

    $this->assertGuest('identity');
});

it('forces the two-factor challenge when requireMfa is requested and a factor is enrolled', function () {
    $factor = app(TotpFactorProvider::class)->enroll($this->user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.id', $this->user->getAuthIdentifier());

    $this->assertGuest('identity');
});

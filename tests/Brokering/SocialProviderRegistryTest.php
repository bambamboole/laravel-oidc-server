<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Brokering\Contracts\SocialProvider;
use Bambamboole\LaravelOidc\Server\Brokering\GoogleProvider;
use Bambamboole\LaravelOidc\Server\Brokering\OidcProvider;
use Bambamboole\LaravelOidc\Server\Brokering\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Brokering\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\SocialUser;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

it('omits providers without credentials and resolves configured ones', function () {
    config()->set('oidc.social.providers.google.client_id', 'g-client');
    config()->set('oidc.social.providers.google.client_secret', 'g-secret');

    $registry = app(SocialProviderRegistry::class);

    expect($registry->get('google'))->toBeInstanceOf(GoogleProvider::class)
        ->and($registry->get('github'))->toBeNull()
        ->and($registry->get('unknown'))->toBeNull()
        ->and(array_keys($registry->enabled()))->toBe(['google']);
});

it('resolves the generic oidc driver from config', function () {
    config()->set('oidc.social.providers.corp', [
        'driver' => 'oidc',
        'issuer' => 'https://idp.test',
        'client_id' => 'client-1',
        'client_secret' => 'shhh',
    ]);

    expect(app(SocialProviderRegistry::class)->get('corp'))->toBeInstanceOf(OidcProvider::class);
});

it('supports custom drivers via extend', function () {
    config()->set('oidc.social.providers.custom', ['driver' => 'my-driver', 'client_id' => 'x']);

    app(SocialProviderRegistry::class)->extend('my-driver', fn (string $key, array $config): SocialProvider => new class($key) implements SocialProvider
    {
        public function __construct(private readonly string $key) {}

        public function key(): string
        {
            return $this->key;
        }

        public function redirect(Request $request, string $intent = PendingAuthorization::INTENT_LOGIN): RedirectResponse
        {
            return redirect()->away('https://custom.test');
        }

        public function user(Request $request, PendingAuthorization $pending): SocialUser
        {
            return new SocialUser('c-1', null, false, null, null, null);
        }
    });

    expect(app(SocialProviderRegistry::class)->get('custom')?->key())->toBe('custom')
        ->and(app(SocialProviderRegistry::class)->enabled())->toHaveKey('custom');
});

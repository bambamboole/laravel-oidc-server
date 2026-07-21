<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Social\Contracts\SocialProvider;
use Bambamboole\LaravelOidc\Auth\Social\GoogleProvider;
use Bambamboole\LaravelOidc\Auth\Social\OidcProvider;
use Bambamboole\LaravelOidc\Auth\Social\PendingAuthorization;
use Bambamboole\LaravelOidc\Auth\Social\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Auth\Social\SocialUser;
use Bambamboole\LaravelOidc\Auth\UserActionManager;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Workbench\App\Models\User;

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

    Oidc::extendSocialProvider('my-driver', fn (string $key, array $config): SocialProvider => new class($key) implements SocialProvider
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
        ->and(Oidc::socialProviders())->toHaveKey('custom');
});

it('creates users from social via the registered action and returns null without one', function () {
    $socialUser = new SocialUser('g-1', 'm@example.com', true, 'M', null, null);

    $manager = app(UserActionManager::class);

    expect($manager->createUserFromSocial($socialUser, 'google'))->toBeNull();

    Oidc::createUsersFromSocialUsing(fn (SocialUser $user, string $provider) => User::create([
        'name' => $user->name ?? 'Unknown',
        'email' => $user->email,
        'password' => Str::random(40),
    ]));

    $created = $manager->createUserFromSocial($socialUser, 'google');

    expect($created)->toBeInstanceOf(User::class);

    $this->assertDatabaseHas('users', ['email' => 'm@example.com']);
});

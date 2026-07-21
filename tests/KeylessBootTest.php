<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Tests;

use Bambamboole\LaravelOidc\Facades\Oidc;
use Bambamboole\LaravelOidc\OidcManager;
use Illuminate\Encryption\MissingAppKeyException;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as BaseTestCase;

/**
 * Locks the keyless-boot guarantee: registering views, actions, and triggers through
 * the Oidc facade in a provider's boot() must never resolve the encrypter,
 * so keyless artisan runs (package:discover on CI / fresh clones) survive.
 */
class KeylessBootTest extends BaseTestCase
{
    use WithWorkbench;

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', '');
    }

    public function test_the_environment_is_genuinely_keyless(): void
    {
        $this->expectException(MissingAppKeyException::class);

        $this->app->make('encrypter');
    }

    public function test_facade_registration_never_resolves_the_encrypter(): void
    {
        Oidc::loginView(fn () => 'login');
        Oidc::confirmPasswordView(fn () => 'confirm');
        Oidc::registerView(fn () => 'register');
        Oidc::requestPasswordResetLinkView(fn () => 'forgot');
        Oidc::resetPasswordView(fn () => 'reset');
        Oidc::verifyEmailView(fn () => 'verify');
        Oidc::twoFactorChallengeView(fn () => 'two-factor');
        Oidc::createUsersUsing(fn (array $input) => throw new \RuntimeException('unused'));
        Oidc::resetUserPasswordsUsing(fn () => null);
        Oidc::createUsersFromSocialUsing(fn () => throw new \RuntimeException('unused'));
        Oidc::postLogin(fn () => null);
        Oidc::clientCredentials(fn () => null);
        Oidc::tokenExchange(fn () => null);
        Oidc::extendSocialProvider('custom', fn () => throw new \RuntimeException('unused'));

        $this->assertInstanceOf(OidcManager::class, $this->app->make(OidcManager::class));
    }
}

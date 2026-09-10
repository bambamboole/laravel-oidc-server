<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tests;

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Brokering\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Server\OidcServiceProvider;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Illuminate\Encryption\MissingAppKeyException;
use Laravel\Passkeys\PasskeysServiceProvider;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as BaseTestCase;

/**
 * Locks the keyless-boot guarantee: registering actions and triggers through
 * the Oidc facade in a provider's boot() must never resolve the encrypter,
 * so keyless artisan runs (package:discover on CI / fresh clones) survive.
 */
class KeylessBootTest extends BaseTestCase
{
    use WithWorkbench;

    protected $enablesPackageDiscoveries = false;

    protected function getPackageProviders($app): array
    {
        return [
            PasskeysServiceProvider::class,
            OidcServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', '');
    }

    public function test_the_environment_is_genuinely_keyless(): void
    {
        $this->expectException(MissingAppKeyException::class);

        $this->app->make('encrypter');
    }

    public function test_hook_registration_never_resolves_the_encrypter(): void
    {
        createUsersUsing(fn (array $input) => throw new \RuntimeException('unused'));
        resetUserPasswordsUsing(fn (): null => null);
        createUsersFromSocialUsing(fn () => throw new \RuntimeException('unused'));
        app(PostLoginPipeline::class)->register(fn (): null => null);
        app(AccessTokenPipeline::class)->register('client_credentials', fn (): null => null);
        app(AccessTokenPipeline::class)->register('token_exchange', fn (): null => null);
        app(SocialProviderRegistry::class)->extend('custom', fn () => throw new \RuntimeException('unused'));

        $this->assertTrue(app(AccessTokenPipeline::class)->has('client_credentials'));
    }
}

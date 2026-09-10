<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials;

use Bambamboole\LaravelOidc\Server\Credentials\Contracts\FactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\Views\FactorSetupView;
use Bambamboole\LaravelOidc\Server\Credentials\Views\TwoFactorChallengeView;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\MissingAuthViewException;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\PasswordCredential;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\SecondFactorGate;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkeys;
use LogicException;

class CredentialsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(TotpFactorProvider::class);
        $this->app->singleton(RecoveryCodeProvider::class);
        $this->app->singleton(WebAuthnFactorProvider::class);
        $this->app->singleton(SecondFactorGate::class, EnrolledFactorGate::class);
        $this->app->singleton(PasswordCredential::class, TrackedPasswordCredential::class);
        $this->app->singleton(FactorRegistry::class, function (Application $app): FactorRegistry {
            $registry = new FactorRegistry($app->make(RealmResolver::class));

            foreach ((array) config('oidc.auth.factors', []) as $provider) {
                $resolved = $app->make($provider);

                if (! $resolved instanceof FactorProvider) {
                    throw new LogicException("The configured factor provider [{$provider}] must implement FactorProvider.");
                }

                $registry->register($resolved);
            }

            return $registry;
        });

        $this->app->bind(TwoFactorChallengeView::class, fn (): never => throw MissingAuthViewException::forContract(TwoFactorChallengeView::class));
        $this->app->bind(FactorSetupView::class, fn (): never => throw MissingAuthViewException::forContract(FactorSetupView::class));

        $this->configurePasskeys();
    }

    /**
     * Passkeys authenticate against the identity guard and are served by the
     * package's own routes, so the passkeys package must neither register its
     * routes nor default to the application guard.
     */
    private function configurePasskeys(): void
    {
        Passkeys::ignoreRoutes();

        config()->set('passkeys.guard', (string) config('oidc.auth.guard', 'identity'));
        config()->set('passkeys.redirect', config('oidc.auth.home', '/dashboard'));
        config()->set('passkeys.middleware', ['web']);
        config()->set('passkeys.management_middleware', []);
        config()->set('passkeys.throttle', 'throttle:5,1');

        $userModel = config('auth.providers.users.model');

        if (is_string($userModel) && is_subclass_of($userModel, PasskeyUser::class)) {
            Passkeys::useUserModel($userModel);
        }
    }
}

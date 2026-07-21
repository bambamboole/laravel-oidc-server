<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc;

use Bambamboole\LaravelOidc\Auth\AccessTokenContextLink;
use Bambamboole\LaravelOidc\Auth\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Auth\AuthViewManager;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\FactorProvider;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Auth\MultiFactor\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Auth\MultiFactor\WebAuthnFactorProvider;
use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Auth\Pipeline\NullDeviceRecognizer;
use Bambamboole\LaravelOidc\Auth\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\Auth\Social\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Auth\UserActionManager;
use Bambamboole\LaravelOidc\BackChannel\BackChannelLogoutNotifier;
use Bambamboole\LaravelOidc\Claims\DefaultClaimsResolver;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Console\DispatchExpiredSessionLogoutsCommand;
use Bambamboole\LaravelOidc\Console\InstallSelfCommand;
use Bambamboole\LaravelOidc\Console\ProvisionClientCommand;
use Bambamboole\LaravelOidc\Console\PruneAuthenticationContextsCommand;
use Bambamboole\LaravelOidc\Console\RotateKeysCommand;
use Bambamboole\LaravelOidc\Contracts\ClaimsResolver;
use Bambamboole\LaravelOidc\Contracts\DeviceRecognizer;
use Bambamboole\LaravelOidc\Contracts\EnvironmentStore;
use Bambamboole\LaravelOidc\Contracts\ExchangePolicy;
use Bambamboole\LaravelOidc\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Contracts\SessionTokenProvider;
use Bambamboole\LaravelOidc\Exchange\DefaultExchangePolicy;
use Bambamboole\LaravelOidc\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Grant\OidcAuthCodeGrant;
use Bambamboole\LaravelOidc\Grant\OidcClientCredentialsGrant;
use Bambamboole\LaravelOidc\Grant\OidcRefreshTokenGrant;
use Bambamboole\LaravelOidc\Grant\TokenExchangeGrant;
use Bambamboole\LaravelOidc\Http\Controllers\AuthorizationController;
use Bambamboole\LaravelOidc\Responses\IdTokenResponse;
use Bambamboole\LaravelOidc\Scopes\BridgeScopeRepository;
use Bambamboole\LaravelOidc\Scopes\DefaultScopeRepository;
use Bambamboole\LaravelOidc\Session\EndOidcSession;
use Bambamboole\LaravelOidc\Session\EstablishSessionToken;
use Bambamboole\LaravelOidc\Session\ForgetSessionToken;
use Bambamboole\LaravelOidc\Session\SessionMintTokenProvider;
use Bambamboole\LaravelOidc\Session\StartOidcSession;
use Bambamboole\LaravelOidc\Support\EnvironmentFile;
use Bambamboole\LaravelOidc\Token\AccessTokenMinter;
use Bambamboole\LaravelOidc\Token\OidcAccessToken;
use Bambamboole\LaravelOidc\Token\OidcAccessTokenRepository;
use DateInterval;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkeys;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportBridgeAccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Bridge\ScopeRepository as PassportBridgeScopeRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;

class OidcServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc.php', 'oidc');

        // Feed the OIDC signing keys into Passport's config so its token guard
        // verifies with the same keypair the package signs with.
        foreach (['private', 'public'] as $type) {
            $key = (string) config("oidc.{$type}_key");

            if ($key !== '') {
                config()->set("passport.{$type}_key", $key);
            }
        }

        $identityGuard = (string) config('oidc.auth.guard', 'identity');

        if (! config()->has("auth.guards.{$identityGuard}")) {
            config()->set("auth.guards.{$identityGuard}", [
                'driver' => 'session',
                'provider' => (string) config('oidc.auth.provider', 'users'),
            ]);
        }

        config()->set('passport.guard', $identityGuard);

        Passport::ignoreRoutes();
        Passport::useAccessTokenEntity(OidcAccessToken::class);
        Passkeys::ignoreRoutes();

        $this->app->singleton(ScopeRepository::class, DefaultScopeRepository::class);
        $this->app->bind(PassportBridgeScopeRepository::class, BridgeScopeRepository::class);
        $this->app->singleton(ClaimsResolver::class, DefaultClaimsResolver::class);
        $this->app->singleton(AuthViewManager::class);
        $this->app->singleton(UserActionManager::class);
        $this->app->singleton(TotpFactorProvider::class);
        $this->app->singleton(RecoveryCodeProvider::class);
        $this->app->singleton(WebAuthnFactorProvider::class);
        $this->app->singleton(SocialProviderRegistry::class);
        $this->app->singleton(FactorRegistry::class, function (Application $app): FactorRegistry {
            $registry = new FactorRegistry;

            foreach ((array) config('oidc.auth.factors', []) as $provider) {
                $resolved = $app->make($provider);

                if (! $resolved instanceof FactorProvider) {
                    throw new \LogicException("The configured factor provider [{$provider}] must implement FactorProvider.");
                }

                $registry->register($resolved);
            }

            return $registry;
        });
        $this->app->bind(
            FirstPartyClientConfig::class,
            fn (): FirstPartyClientConfig => FirstPartyClientConfig::fromConfig(),
        );
        $this->app->singleton(FirstPartyClientProvisioner::class);
        $this->app->singleton(EnvironmentStore::class, EnvironmentFile::class);
        $this->app->singleton(OidcManager::class);
        $this->app->singleton(ExchangePolicy::class, DefaultExchangePolicy::class);
        $this->app->singleton(AccessTokenMinter::class);
        $this->app->singleton(TokenExchanger::class);
        $this->app->singleton(SessionTokenProvider::class, SessionMintTokenProvider::class);
        $this->app->singleton(AccessTokenPipeline::class);
        $this->app->bind(PassportBridgeAccessTokenRepository::class, OidcAccessTokenRepository::class);
        $this->app->singleton(PostLoginPipeline::class);
        $this->app->singleton(AuthenticationContextStore::class);
        $this->app->singleton(SessionRegistry::class);
        $this->app->singleton(BackChannelLogoutNotifier::class);
        $this->app->singleton(AccessTokenContextLink::class);
        $this->app->singleton(DeviceRecognizer::class, NullDeviceRecognizer::class);

        config()->set('passkeys.guard', $identityGuard);
        config()->set('passkeys.redirect', config('oidc.auth.home', '/dashboard'));
        config()->set('passkeys.middleware', ['web']);
        config()->set('passkeys.management_middleware', []);
        config()->set('passkeys.throttle', 'throttle:5,1');

        $userModel = config('auth.providers.users.model');

        if (is_string($userModel) && is_subclass_of($userModel, PasskeyUser::class)) {
            Passkeys::useUserModel($userModel);
        }

        $this->app->when(AuthorizationController::class)
            ->needs(StatefulGuard::class)
            ->give(fn () => Auth::guard(config('passport.guard', null)));

        $this->app->extend(AuthorizationServer::class, function (AuthorizationServer $server, Application $app): AuthorizationServer {
            $accessTokenTtl = new DateInterval('PT'.(int) config('oidc.token_lifetimes.access_token').'S');

            $grant = new OidcAuthCodeGrant(
                $app->make(AuthCodeRepository::class),
                $app->make(RefreshTokenRepository::class),
                new DateInterval('PT10M'),
            );
            $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

            $server->enableGrantType($grant, $accessTokenTtl);

            $refreshGrant = new OidcRefreshTokenGrant($app->make(RefreshTokenRepository::class));
            $refreshGrant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
            $server->enableGrantType($refreshGrant, $accessTokenTtl);

            $server->enableGrantType(
                new OidcClientCredentialsGrant($app->make(AccessTokenPipeline::class)),
                new DateInterval('PT'.(int) config('oidc.token_lifetimes.client_credentials').'S'),
            );

            if (config('oidc.token_exchange.enabled', true)) {
                $server->enableGrantType(
                    new TokenExchangeGrant(
                        $app->make(TokenExchanger::class),
                    ),
                    Passport::tokensExpireIn(),
                );
            }

            return $server;
        });
    }

    public function boot(): void
    {
        Passport::useAuthorizationServerResponseType($this->app->make(IdTokenResponse::class));

        Event::listen(Login::class, EstablishSessionToken::class);
        Event::listen(Login::class, StartOidcSession::class);
        Event::listen(Logout::class, ForgetSessionToken::class);
        Event::listen(Logout::class, EndOidcSession::class);

        ResetPassword::createUrlUsing(fn (mixed $notifiable, string $token): string => url(route(
            'identity.password.reset',
            ['token' => $token, 'email' => $notifiable->getEmailForPasswordReset()],
            false,
        )));
        VerifyEmail::createUrlUsing(fn (mixed $notifiable): string => URL::temporarySignedRoute(
            'identity.verification.verify',
            Carbon::now()->addMinutes((int) config('auth.verification.expire', 60)),
            ['id' => $notifiable->getKey(), 'hash' => sha1($notifiable->getEmailForVerification())],
        ));

        $this->loadRoutesFrom(__DIR__.'/../routes/oidc.php');

        $this->publishes([
            __DIR__.'/../config/oidc.php' => config_path('oidc.php'),
        ], 'oidc-config');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'oidc-migrations');

        if ($this->app->runningInConsole()) {
            $this->commands([
                ProvisionClientCommand::class,
                InstallSelfCommand::class,
                PruneAuthenticationContextsCommand::class,
                DispatchExpiredSessionLogoutsCommand::class,
                RotateKeysCommand::class,
            ]);
        }
    }
}

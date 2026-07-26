<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server;

use Bambamboole\LaravelOidc\Server\Auth\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\FactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\WebAuthnFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\Contracts\DeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\NullDeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Auth\Social\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Server\Auth\UserActionManager;
use Bambamboole\LaravelOidc\Server\Auth\Views\ConsentPrompt;
use Bambamboole\LaravelOidc\Server\Auth\Views\ConsentView;
use Bambamboole\LaravelOidc\Server\Auth\Views\EmailVerificationView;
use Bambamboole\LaravelOidc\Server\Auth\Views\LoginView;
use Bambamboole\LaravelOidc\Server\Auth\Views\MissingAuthViewException;
use Bambamboole\LaravelOidc\Server\Auth\Views\PasswordConfirmationView;
use Bambamboole\LaravelOidc\Server\Auth\Views\PasswordResetRequestView;
use Bambamboole\LaravelOidc\Server\Auth\Views\PasswordResetView;
use Bambamboole\LaravelOidc\Server\Auth\Views\RegisterView;
use Bambamboole\LaravelOidc\Server\Auth\Views\TwoFactorChallengeView;
use Bambamboole\LaravelOidc\Server\BackChannel\BackChannelLogoutNotifier;
use Bambamboole\LaravelOidc\Server\Claims\DefaultClaimsResolver;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Server\Console\DispatchExpiredSessionLogoutsCommand;
use Bambamboole\LaravelOidc\Server\Console\InstallSelfCommand;
use Bambamboole\LaravelOidc\Server\Console\ProvisionClientCommand;
use Bambamboole\LaravelOidc\Server\Console\PruneAuthenticationContextsCommand;
use Bambamboole\LaravelOidc\Server\Console\RotateKeysCommand;
use Bambamboole\LaravelOidc\Server\Context\AccessTokenContextLink;
use Bambamboole\LaravelOidc\Server\Context\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Server\Contracts\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Contracts\ExchangePolicy;
use Bambamboole\LaravelOidc\Server\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Contracts\SessionTokenProvider;
use Bambamboole\LaravelOidc\Server\Exchange\DefaultExchangePolicy;
use Bambamboole\LaravelOidc\Server\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Server\Grant\OidcAuthCodeGrant;
use Bambamboole\LaravelOidc\Server\Grant\OidcClientCredentialsGrant;
use Bambamboole\LaravelOidc\Server\Grant\OidcRefreshTokenGrant;
use Bambamboole\LaravelOidc\Server\Grant\TokenExchangeGrant;
use Bambamboole\LaravelOidc\Server\Http\Controllers\AuthorizationController;
use Bambamboole\LaravelOidc\Server\Responses\IdTokenResponse;
use Bambamboole\LaravelOidc\Server\Scopes\BridgeScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\DefaultScopeRepository;
use Bambamboole\LaravelOidc\Server\Session\EndOidcSession;
use Bambamboole\LaravelOidc\Server\Session\EstablishSessionToken;
use Bambamboole\LaravelOidc\Server\Session\ForgetSessionToken;
use Bambamboole\LaravelOidc\Server\Session\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Session\SessionMintTokenProvider;
use Bambamboole\LaravelOidc\Server\Session\StartOidcSession;
use Bambamboole\LaravelOidc\Server\Support\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Support\EnvironmentStore;
use Bambamboole\LaravelOidc\Server\Support\PassportConfigurator;
use Bambamboole\LaravelOidc\Server\Token\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Token\OidcAccessToken;
use Bambamboole\LaravelOidc\Server\Token\OidcAccessTokenRepository;
use DateInterval;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Request;
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
use Symfony\Component\HttpFoundation\Response;

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
        $this->app->singleton(OidcSessionRepository::class);
        $this->app->singleton(BackChannelLogoutNotifier::class);
        $this->app->singleton(AccessTokenContextLink::class);
        $this->app->singleton(DeviceRecognizer::class, NullDeviceRecognizer::class);

        $this->registerDefaultAuthViewBindings();

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
                $app->make(AccessTokenContextLink::class),
                $app->make(AccessTokenPipeline::class),
                $app->make(AuthenticationContextStore::class),
                $app->make(OidcSessionRepository::class),
                $app->make(AuthSessionState::class),
            );
            $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

            $server->enableGrantType($grant, $accessTokenTtl);

            $refreshGrant = new OidcRefreshTokenGrant(
                $app->make(RefreshTokenRepository::class),
                $app->make(AccessTokenContextLink::class),
                $app->make(AccessTokenPipeline::class),
                $app->make(AuthenticationContextStore::class),
                $app->make(OidcSessionRepository::class),
            );
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

    /**
     * Every auth surface resolves through the container: without a ui
     * package or app binding, the default throws so the missing view is
     * caught at development time instead of rendering nothing.
     */
    private function registerDefaultAuthViewBindings(): void
    {
        foreach ([
            LoginView::class,
            RegisterView::class,
            PasswordResetRequestView::class,
            PasswordResetView::class,
            EmailVerificationView::class,
            PasswordConfirmationView::class,
            TwoFactorChallengeView::class,
            ConsentView::class,
        ] as $contract) {
            $this->app->bind($contract, fn (): never => throw MissingAuthViewException::forContract($contract));
        }
    }

    public function boot(): void
    {
        $this->app->make(PassportConfigurator::class)();

        Passport::useAuthorizationServerResponseType($this->app->make(IdTokenResponse::class));

        // The only Passport view seam the package wires: every consent
        // render resolves the ConsentView contract from the container, so
        // overriding consent (or getting the "missing view" exception) is
        // identical to every other auth surface.
        Passport::authorizationView(
            fn (array $parameters): Responsable|Response => $this->app->make(ConsentView::class)->respond(
                new ConsentPrompt(
                    client: $parameters['client'],
                    user: $parameters['user'],
                    scopes: $parameters['scopes'],
                    authToken: $parameters['authToken'],
                ),
                Request::instance(),
            ),
        );

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

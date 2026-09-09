<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Audit\LogSink;
use Bambamboole\LaravelOidc\Server\Audit\RecordLoginAudit;
use Bambamboole\LaravelOidc\Server\Audit\RecordLogoutAudit;
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
use Bambamboole\LaravelOidc\Server\Bridge\AccessTokenRepository;
use Bambamboole\LaravelOidc\Server\Bridge\AuthCodeRepository;
use Bambamboole\LaravelOidc\Server\Bridge\ClientRepository as BridgeClientRepository;
use Bambamboole\LaravelOidc\Server\Bridge\RefreshTokenRepository;
use Bambamboole\LaravelOidc\Server\Bridge\UserRepository;
use Bambamboole\LaravelOidc\Server\Claims\DefaultClaimsResolver;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Server\Console\DispatchExpiredSessionLogoutsCommand;
use Bambamboole\LaravelOidc\Server\Console\InstallSelfCommand;
use Bambamboole\LaravelOidc\Server\Console\ProvisionClientCommand;
use Bambamboole\LaravelOidc\Server\Console\PruneAuthenticationContextsCommand;
use Bambamboole\LaravelOidc\Server\Console\PurgeTokensCommand;
use Bambamboole\LaravelOidc\Server\Console\RotateKeysCommand;
use Bambamboole\LaravelOidc\Server\Context\AccessTokenContextLink;
use Bambamboole\LaravelOidc\Server\Context\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Server\Contracts\AuditSink;
use Bambamboole\LaravelOidc\Server\Contracts\AuthorizationViewResponse;
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
use Bambamboole\LaravelOidc\Server\Http\Responses\ConsentViewResponse;
use Bambamboole\LaravelOidc\Server\Realm\ConfiguredRealmResolver;
use Bambamboole\LaravelOidc\Server\Realm\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Realm\RealmIssuerResolver;
use Bambamboole\LaravelOidc\Server\Realm\RealmResolver;
use Bambamboole\LaravelOidc\Server\Realm\RouteRealmResolver;
use Bambamboole\LaravelOidc\Server\Scopes\BridgeScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\DefaultScopeRepository;
use Bambamboole\LaravelOidc\Server\Server\AuthorizationServerFactory;
use Bambamboole\LaravelOidc\Server\Session\EndOidcSession;
use Bambamboole\LaravelOidc\Server\Session\EstablishSessionToken;
use Bambamboole\LaravelOidc\Server\Session\ForgetSessionToken;
use Bambamboole\LaravelOidc\Server\Session\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Session\SessionMintTokenProvider;
use Bambamboole\LaravelOidc\Server\Session\SessionTokenGuard;
use Bambamboole\LaravelOidc\Server\Session\StartOidcSession;
use Bambamboole\LaravelOidc\Server\Support\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Token\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Token\EnvSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Token\OidcAccessTokenGuard;
use Bambamboole\LaravelOidc\Server\Token\SigningKeys;
use Bambamboole\LaravelOidc\Server\Token\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Token\TokenInspector;
use Bambamboole\LaravelOidc\Server\Token\TokenLifetimes;
use DateInterval;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkeys;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use Throwable;

class OidcServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc.php', 'oidc');

        $identityGuard = (string) config('oidc.auth.guard', 'identity');

        if (! config()->has("auth.guards.{$identityGuard}")) {
            config()->set("auth.guards.{$identityGuard}", [
                'driver' => 'session',
                'provider' => (string) config('oidc.auth.provider', 'users'),
            ]);
        }

        $apiGuard = (string) config('oidc.api_guard', 'oidc');

        if (! config()->has("auth.guards.{$apiGuard}")) {
            config()->set("auth.guards.{$apiGuard}", [
                'driver' => 'oidc',
                'provider' => (string) config('oidc.auth.provider', 'users'),
            ]);
        }

        Auth::resolved(fn ($auth) => $auth->extend('oidc', fn ($app, $name, array $config): OidcAccessTokenGuard => tap(
            new OidcAccessTokenGuard(
                $app->make(TokenInspector::class),
                $auth->createUserProvider($config['provider'] ?? null),
                $app->make('request'),
            ),
            fn (OidcAccessTokenGuard $guard) => $app->refresh('request', $guard, 'setRequest'),
        )));

        Passkeys::ignoreRoutes();

        $this->app->scoped(RealmResolver::class, fn (): RealmResolver => new RouteRealmResolver(new ConfiguredRealmResolver));
        $this->app->scoped(IssuerResolver::class, RealmIssuerResolver::class);
        $this->app->singleton(ScopeRepository::class, DefaultScopeRepository::class);
        $this->app->bind(ScopeRepositoryInterface::class, BridgeScopeRepository::class);
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
        $this->app->singleton(EnvironmentFile::class);
        $this->app->singleton(SigningKeyStore::class, fn (Application $app): SigningKeyStore => $app->make(
            (string) config('oidc.keys.store', EnvSigningKeyStore::class),
        ));
        $this->app->singleton(SigningKeys::class);
        $this->app->singleton(OidcManager::class);
        $this->app->singleton(ExchangePolicy::class, DefaultExchangePolicy::class);
        $this->app->singleton(AccessTokenMinter::class);
        $this->app->singleton(TokenExchanger::class);
        $this->app->singleton(SessionTokenProvider::class, SessionMintTokenProvider::class);
        $this->app->singleton(AccessTokenPipeline::class);
        $this->app->bind(AccessTokenRepositoryInterface::class, AccessTokenRepository::class);
        $this->app->bind(ClientRepositoryInterface::class, BridgeClientRepository::class);
        $this->app->bind(RefreshTokenRepositoryInterface::class, RefreshTokenRepository::class);
        $this->app->bind(AuthCodeRepositoryInterface::class, AuthCodeRepository::class);
        $this->app->bind(UserRepositoryInterface::class, UserRepository::class);
        $this->app->bind(AuthorizationViewResponse::class, ConsentViewResponse::class);
        $this->app->singleton(TokenLifetimes::class);
        $this->app->scoped(AuthorizationServer::class, fn (Application $app): AuthorizationServer => $app
            ->make(AuthorizationServerFactory::class)
            ->make());
        $this->app->singleton(PostLoginPipeline::class);
        $this->app->singleton(AuthenticationContextStore::class);
        $this->app->singleton(OidcSessionRepository::class);
        $this->app->singleton(BackChannelLogoutNotifier::class);
        $this->app->singleton(AccessTokenContextLink::class);
        $this->app->singleton(DeviceRecognizer::class, NullDeviceRecognizer::class);
        $this->app->singleton(AuditSink::class, fn (Application $app): AuditSink => $app->make(
            (string) config('oidc.audit.sink', LogSink::class),
        ));
        $this->app->singleton(Auditor::class);

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
            ->give(fn () => Auth::guard((string) config('oidc.auth.guard', 'identity')));

        $this->app->extend(AuthorizationServer::class, function (AuthorizationServer $server, Application $app): AuthorizationServer {
            $lifetimes = $app->make(TokenLifetimes::class);
            $accessTokenTtl = $lifetimes->accessToken();

            $grant = new OidcAuthCodeGrant(
                $app->make(AuthCodeRepository::class),
                $app->make(RefreshTokenRepository::class),
                new DateInterval('PT10M'),
                $app->make(AccessTokenContextLink::class),
                $app->make(AccessTokenPipeline::class),
                $app->make(AuthenticationContextStore::class),
                $app->make(OidcSessionRepository::class),
                $app->make(AuthSessionState::class),
                $app->make(Auditor::class),
            );
            $grant->setRefreshTokenTTL($lifetimes->refreshToken());

            $server->enableGrantType($grant, $accessTokenTtl);

            $refreshGrant = new OidcRefreshTokenGrant(
                $app->make(RefreshTokenRepository::class),
                $app->make(AccessTokenContextLink::class),
                $app->make(AccessTokenPipeline::class),
                $app->make(AuthenticationContextStore::class),
                $app->make(OidcSessionRepository::class),
                $app->make(Auditor::class),
            );
            $refreshGrant->setRefreshTokenTTL($lifetimes->refreshToken());
            $server->enableGrantType($refreshGrant, $accessTokenTtl);

            $server->enableGrantType(
                new OidcClientCredentialsGrant($app->make(AccessTokenPipeline::class), $app->make(Auditor::class)),
                $lifetimes->clientCredentials(),
            );

            if (config('oidc.token_exchange.enabled', true)) {
                $server->enableGrantType(
                    new TokenExchangeGrant(
                        $app->make(TokenExchanger::class),
                    ),
                    $accessTokenTtl,
                );
            }

            $auditClientAuthFailure = function (RequestEvent $event) use ($app): void {
                $body = $event->getRequest()->getParsedBody();
                $clientId = is_array($body) ? ($body['client_id'] ?? null) : null;
                $clientId = is_string($clientId) ? $clientId : ($event->getRequest()->getQueryParams()['client_id'] ?? null);
                $app->make(Auditor::class)->log(AuditEventType::ClientAuthenticationFailed, clientId: is_string($clientId) ? $clientId : null, context: [
                    'endpoint' => trim($event->getRequest()->getUri()->getPath(), '/'),
                    'reason' => $event->eventName(),
                ]);
            };
            $server->getEmitter()->subscribeTo(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $auditClientAuthFailure);
            $server->getEmitter()->subscribeTo(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $auditClientAuthFailure);

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
        // RecordLoginAudit runs after StartOidcSession so the sid it captures
        // exists; RecordLogoutAudit runs before the teardown listeners so the
        // sid is still readable from the session.
        Event::listen(Login::class, EstablishSessionToken::class);
        Event::listen(Login::class, StartOidcSession::class);
        Event::listen(Login::class, RecordLoginAudit::class);
        Event::listen(Logout::class, RecordLogoutAudit::class);
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

        // Route generation outside a matched route — console commands, queued
        // notifications — has no realm to fall back on; ResolveRealm overrides
        // this per request.
        URL::defaults(['realm' => (string) config('oidc.realm', 'default')]);

        $this->loadRoutesFrom(__DIR__.'/../routes/oidc.php');

        $this->publishes([
            __DIR__.'/../config/oidc.php' => config_path('oidc.php'),
        ], 'oidc-config');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'oidc-migrations');

        AboutCommand::add('OIDC', fn (): array => [
            'Issuer' => config('oidc.issuer') ?? 'not set',
            'Auth Guard' => config('oidc.auth.guard'),
            'Session Token Guard' => SessionTokenGuard::name() ?? 'not set',
            'Self-SSO Client' => FirstPartyClientConfig::fromConfig()->isConfigured() ? 'configured' : 'not configured',
            'Signing Key Store' => class_basename((string) config('oidc.keys.store', EnvSigningKeyStore::class)),
            'Signing Key' => $this->activeSigningKid(),
        ]);

        if ($this->app->runningInConsole()) {
            $this->commands([
                ProvisionClientCommand::class,
                InstallSelfCommand::class,
                PruneAuthenticationContextsCommand::class,
                DispatchExpiredSessionLogoutsCommand::class,
                PurgeTokensCommand::class,
                RotateKeysCommand::class,
            ]);
        }
    }

    private function activeSigningKid(): string
    {
        try {
            return $this->app->make(SigningKeyStore::class)->signingKey()->kid();
        } catch (Throwable) {
            return 'missing';
        }
    }
}

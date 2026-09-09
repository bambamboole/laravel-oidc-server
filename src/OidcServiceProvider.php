<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server;

use Bambamboole\LaravelOidc\Server\Audit\AuditServiceProvider;
use Bambamboole\LaravelOidc\Server\Audit\RecordLoginAudit;
use Bambamboole\LaravelOidc\Server\Audit\RecordLogoutAudit;
use Bambamboole\LaravelOidc\Server\Authentication\AuthenticationServiceProvider;
use Bambamboole\LaravelOidc\Server\BackChannel\BackChannelServiceProvider;
use Bambamboole\LaravelOidc\Server\Brokering\BrokeringServiceProvider;
use Bambamboole\LaravelOidc\Server\Claims\ClaimsServiceProvider;
use Bambamboole\LaravelOidc\Server\Clients\ClientsServiceProvider;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Console\InstallSelfCommand;
use Bambamboole\LaravelOidc\Server\Context\ContextServiceProvider;
use Bambamboole\LaravelOidc\Server\Credential\CredentialServiceProvider;
use Bambamboole\LaravelOidc\Server\Exchange\ExchangeServiceProvider;
use Bambamboole\LaravelOidc\Server\Forms\FormsServiceProvider;
use Bambamboole\LaravelOidc\Server\Keys\EnvSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Keys\KeysServiceProvider;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Realm\RealmServiceProvider;
use Bambamboole\LaravelOidc\Server\Scopes\ScopesServiceProvider;
use Bambamboole\LaravelOidc\Server\Server\AuthorizationServerServiceProvider;
use Bambamboole\LaravelOidc\Server\Session\EndOidcSession;
use Bambamboole\LaravelOidc\Server\Session\EstablishSessionToken;
use Bambamboole\LaravelOidc\Server\Session\ForgetSessionToken;
use Bambamboole\LaravelOidc\Server\Session\SessionServiceProvider;
use Bambamboole\LaravelOidc\Server\Session\SessionTokenGuard;
use Bambamboole\LaravelOidc\Server\Session\StartOidcSession;
use Bambamboole\LaravelOidc\Server\Support\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Token\TokenServiceProvider;
use Bambamboole\LaravelOidc\Server\User\UserServiceProvider;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Throwable;

class OidcServiceProvider extends ServiceProvider
{
    /**
     * Each domain wires its own bindings and commands; this provider owns
     * what spans them: config, routes, publishing, and the login/logout
     * listener order.
     *
     * @var list<class-string<ServiceProvider>>
     */
    private const DOMAIN_PROVIDERS = [
        RealmServiceProvider::class,
        KeysServiceProvider::class,
        ScopesServiceProvider::class,
        ClaimsServiceProvider::class,
        UserServiceProvider::class,
        CredentialServiceProvider::class,
        BrokeringServiceProvider::class,
        ClientsServiceProvider::class,
        ExchangeServiceProvider::class,
        TokenServiceProvider::class,
        AuthenticationServiceProvider::class,
        SessionServiceProvider::class,
        ContextServiceProvider::class,
        BackChannelServiceProvider::class,
        AuditServiceProvider::class,
        FormsServiceProvider::class,
        AuthorizationServerServiceProvider::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc.php', 'oidc');

        foreach (self::DOMAIN_PROVIDERS as $provider) {
            $this->app->register($provider);
        }

        $this->app->singleton(EnvironmentFile::class);
        $this->app->singleton(OidcManager::class);
    }

    public function boot(): void
    {
        // RecordLoginAudit runs after StartOidcSession so the sid it captures
        // exists; RecordLogoutAudit runs before the teardown listeners so the
        // sid is still readable from the session. The order crosses the
        // Session and Audit domains, so it is wired here rather than in either.
        Event::listen(Login::class, EstablishSessionToken::class);
        Event::listen(Login::class, StartOidcSession::class);
        Event::listen(Login::class, RecordLoginAudit::class);
        Event::listen(Logout::class, RecordLogoutAudit::class);
        Event::listen(Logout::class, ForgetSessionToken::class);
        Event::listen(Logout::class, EndOidcSession::class);

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
            $this->commands([InstallSelfCommand::class]);
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

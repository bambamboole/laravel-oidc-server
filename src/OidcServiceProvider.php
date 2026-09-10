<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server;

use Bambamboole\LaravelOidc\Server\Audit\AuditServiceProvider;
use Bambamboole\LaravelOidc\Server\Authentication\AuthenticationServiceProvider;
use Bambamboole\LaravelOidc\Server\Brokering\BrokeringServiceProvider;
use Bambamboole\LaravelOidc\Server\Clients\ClientsServiceProvider;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Consents\ConsentsServiceProvider;
use Bambamboole\LaravelOidc\Server\Credentials\CredentialsServiceProvider;
use Bambamboole\LaravelOidc\Server\Installation\InstallationServiceProvider;
use Bambamboole\LaravelOidc\Server\Keys\EnvSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Keys\KeysServiceProvider;
use Bambamboole\LaravelOidc\Server\Protocol\ProtocolServiceProvider;
use Bambamboole\LaravelOidc\Server\Realms\RealmRouting;
use Bambamboole\LaravelOidc\Server\Realms\RealmsServiceProvider;
use Bambamboole\LaravelOidc\Server\Scopes\ScopesServiceProvider;
use Bambamboole\LaravelOidc\Server\Sessions\SessionsServiceProvider;
use Bambamboole\LaravelOidc\Server\Sessions\SessionTokenGuard;
use Bambamboole\LaravelOidc\Server\Shared\Installation\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Tokens\TokensServiceProvider;
use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\ServiceProvider;
use Throwable;

class OidcServiceProvider extends ServiceProvider
{
    /**
     * Each domain wires its own bindings, listeners and commands; this
     * provider owns what spans them: config, routes and publishing. The order
     * is also the boot order: Sessions must precede Audit so the login audit
     * finds the sid StartOidcSession wrote.
     *
     * @var list<class-string<ServiceProvider>>
     */
    private const array DOMAIN_PROVIDERS = [
        RealmsServiceProvider::class,
        KeysServiceProvider::class,
        ScopesServiceProvider::class,
        CredentialsServiceProvider::class,
        BrokeringServiceProvider::class,
        ClientsServiceProvider::class,
        TokensServiceProvider::class,
        AuthenticationServiceProvider::class,
        SessionsServiceProvider::class,
        ConsentsServiceProvider::class,
        AuditServiceProvider::class,
        ProtocolServiceProvider::class,
        InstallationServiceProvider::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc.php', 'oidc');

        // Written by the Keys, Clients and Installation commands alike, so it
        // is bound where all of them are wired.
        $this->app->singleton(EnvironmentFile::class);

        foreach (self::DOMAIN_PROVIDERS as $provider) {
            $this->app->register($provider);
        }
    }

    public function boot(): void
    {
        // OIDC Core §3.1.2.1: clients POST authorization requests cross-site,
        // so the web group's forgery check must not apply to that route.
        PreventRequestForgery::except(RealmRouting::configured()->pattern('oauth/authorize'));

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

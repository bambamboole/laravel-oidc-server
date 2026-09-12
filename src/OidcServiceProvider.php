<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server;

use Bambamboole\LaravelOidc\Server\Audit\AuditServiceProvider;
use Bambamboole\LaravelOidc\Server\Authentication\AuthenticationServiceProvider;
use Bambamboole\LaravelOidc\Server\Authentication\RequiredActions\UpdatePasswordAction;
use Bambamboole\LaravelOidc\Server\Authentication\RequiredActions\VerifyEmailAction;
use Bambamboole\LaravelOidc\Server\Brokering\BrokeringServiceProvider;
use Bambamboole\LaravelOidc\Server\Clients\ClientsServiceProvider;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Consents\ConsentsServiceProvider;
use Bambamboole\LaravelOidc\Server\Credentials\ConfigureMfaAction;
use Bambamboole\LaravelOidc\Server\Credentials\CredentialsServiceProvider;
use Bambamboole\LaravelOidc\Server\Installation\InstallationServiceProvider;
use Bambamboole\LaravelOidc\Server\Protocol\ProtocolServiceProvider;
use Bambamboole\LaravelOidc\Server\Purge\Commands\PruneCommand;
use Bambamboole\LaravelOidc\Server\Realms\Enums\RealmRouting;
use Bambamboole\LaravelOidc\Server\Realms\RealmsServiceProvider;
use Bambamboole\LaravelOidc\Server\Scopes\ScopesServiceProvider;
use Bambamboole\LaravelOidc\Server\Sessions\SessionsServiceProvider;
use Bambamboole\LaravelOidc\Server\Sessions\SessionTokenGuard;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\IdentityGuard;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\RequiredActionRegistry;
use Bambamboole\LaravelOidc\Server\Shared\Installation\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\SigningKeys\DatabaseSigningKeyStore;
use Bambamboole\LaravelOidc\Server\SigningKeys\SigningKeysServiceProvider;
use Bambamboole\LaravelOidc\Server\Tokens\TokensServiceProvider;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Arr;
use Illuminate\Support\ServiceProvider;
use Throwable;

class OidcServiceProvider extends ServiceProvider
{
    /**
     * Each domain wires its own bindings, listeners and commands; this
     * provider owns what spans them: config, routes and publishing.
     *
     * @var list<class-string<ServiceProvider>>
     */
    private const array DOMAIN_PROVIDERS = [
        RealmsServiceProvider::class,
        SigningKeysServiceProvider::class,
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

    /**
     * Config keys holding a registry: a map of named entries the package ships
     * defaults for. `mergeConfigFrom` merges only the first level, so a
     * published `config/oidc.php` would freeze these maps at the shape they had
     * when it was published and never see an entry a later release adds. This
     * is what Laravel's own loader does for `database.connections` and its
     * siblings (`LoadConfiguration::mergeableOptions`): merge the map by name,
     * so the application's entry always wins whole and is never patched into.
     *
     * Merging runs at every segment of the path, so a registry nested under a
     * group keeps that group's other keys too — without it, an application that
     * defines `social.providers` would lose `social.link_by_verified_email`.
     * Only the declared paths are descended into; nothing else is.
     *
     * `resources` and `routes.domains` ship empty today; they are listed
     * because they are registries, not because they currently merge anything.
     *
     * @var list<string>
     */
    private const array MERGEABLE_REGISTRIES = [
        'resources',
        'social.providers',
        'routes.domains',
    ];

    public function register(): void
    {
        $this->mergeConfig();

        // Written by both the Clients and Installation commands, so it is bound
        // where the two are wired.
        $this->app->singleton(EnvironmentFile::class);

        // The built-in required actions come from two domains and the order a
        // user is walked through them is a decision above both, so the
        // registry is wired here rather than by either. An application
        // appends its own to it.
        $this->app->singleton(RequiredActionRegistry::class, function (Application $app): RequiredActionRegistry {
            $registry = new RequiredActionRegistry;
            $registry->register(
                $app->make(VerifyEmailAction::class),
                $app->make(UpdatePasswordAction::class),
                $app->make(ConfigureMfaAction::class),
            );

            return $registry;
        });

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

        if ($this->app->runningInConsole()) {
            $this->commands([PruneCommand::class]);
        }

        AboutCommand::add('OIDC', fn (): array => [
            'Issuer' => config('oidc.issuer') ?? 'not set',
            'Auth Guard' => IdentityGuard::name(),
            'Session Token Guard' => SessionTokenGuard::name() ?? 'not set',
            'Self-SSO Client' => FirstPartyClientConfig::fromConfig()->isConfigured() ? 'configured' : 'not configured',
            'Signing Key Store' => class_basename((string) config('oidc.keys.store', DatabaseSigningKeyStore::class)),
            'Signing Key' => $this->activeSigningKid(),
        ]);
    }

    private function mergeConfig(): void
    {
        $path = __DIR__.'/../config/oidc.php';

        $this->mergeConfigFrom($path, 'oidc');

        if ($this->app instanceof CachesConfiguration && $this->app->configurationIsCached()) {
            return;
        }

        $shipped = require $path;
        $config = $this->app->make(ConfigRepository::class);

        foreach (self::MERGEABLE_REGISTRIES as $registry) {
            $walked = [];

            foreach (explode('.', $registry) as $segment) {
                $walked[] = $segment;
                $key = implode('.', $walked);

                $defaults = Arr::get($shipped, $key);
                $configured = $config->get("oidc.{$key}");

                if (is_array($defaults) && is_array($configured)) {
                    $config->set("oidc.{$key}", array_merge($defaults, $configured));
                }
            }
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

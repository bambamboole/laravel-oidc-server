<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tests;

use Bambamboole\LaravelOidc\Server\OidcServiceProvider;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\GeneratedSigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\Jwk;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Tests\Realms\RoutesRealmsByDomain;
use Bambamboole\LaravelOidc\Server\Tests\Realms\RoutesRealmsByPath;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\ParallelTesting;
use Laravel\Passkeys\Passkeys;
use Laravel\Passkeys\PasskeysServiceProvider;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as BaseTestCase;
use Workbench\App\Models\User;

abstract class TestCase extends BaseTestCase
{
    use WithLaravelMigrations;
    use WithWorkbench;

    protected $enablesPackageDiscoveries = false;

    public const string TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';

    /**
     * Only this package's providers: the suite must prove the server works without the
     * client or ui packages that share this monorepo's vendor directory.
     */
    protected function getPackageProviders($app): array
    {
        return [
            PasskeysServiceProvider::class,
            OidcServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $token = ParallelTesting::token();
        $workspace = sys_get_temp_dir().'/laravel-oidc-package-tests';
        $database = $token
            ? $workspace.'/test_'.$token.'.sqlite'
            : $workspace.'/database-'.getmypid().'.sqlite';

        File::makeDirectory(dirname($database), 0755, true, true);

        if (! file_exists($database)) {
            touch($database);
        }

        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite.database', $database);
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('auth.guards.api', ['driver' => 'oidc', 'provider' => 'users']);
        $app['config']->set('session.driver', 'array');

        $uses = class_uses_recursive($this);

        if (in_array(RoutesRealmsByPath::class, $uses, true)) {
            $app['config']->set('oidc.routes.realms', 'path');
        }

        if (in_array(RoutesRealmsByDomain::class, $uses, true)) {
            // Every host must name a realm in `domain` routing, the harness's own included.
            $app['config']->set('oidc.routes.realms', 'domain');
            $app['config']->set('oidc.routes.domains', ['localhost' => 'default']);
        }
    }

    protected function setUp(): void
    {
        parent::setUp();

        Http::preventStrayRequests();

        $this->installFixtureSigningKey();
    }

    /**
     * The fixture keypair keeps kids stable across the suite, so tests may
     * compare against the checked-in public key.
     */
    private function installFixtureSigningKey(): void
    {
        $publicKey = (string) file_get_contents(__DIR__.'/fixtures/oauth-public.key');

        app(SigningKeyStore::class)->rotate(new GeneratedSigningKeys(
            privateKeyPem: (string) file_get_contents(__DIR__.'/fixtures/oauth-private.key'),
            publicKeyPem: $publicKey,
            kid: Jwk::fromPem($publicKey)['kid'],
        ));
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__, 3).'/workbench/database/migrations');
        $this->loadMigrationsFrom(Passkeys::migrationPath());
        $this->loadMigrationsFrom(dirname(__DIR__).'/database/migrations');
    }
}

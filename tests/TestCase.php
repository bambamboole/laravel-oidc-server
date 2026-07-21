<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Tests;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\ParallelTesting;
use Laravel\Passkeys\Passkeys;
use Laravel\Passport\Passport;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as BaseTestCase;
use Workbench\App\Models\User;

abstract class TestCase extends BaseTestCase
{
    use WithLaravelMigrations;
    use WithWorkbench;

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
        $app['config']->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'users']);
        $app['config']->set('session.driver', 'array');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Passport::$validateKeyPermissions = false;
        Passport::loadKeysFrom(__DIR__.'/fixtures');
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__).'/vendor/laravel/passport/database/migrations');
        $this->loadMigrationsFrom(Passkeys::migrationPath());
        $this->loadMigrationsFrom(dirname(__DIR__).'/database/migrations');
    }
}

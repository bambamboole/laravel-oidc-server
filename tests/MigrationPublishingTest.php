<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\OidcServiceProvider;
use Illuminate\Support\Facades\File;
use Illuminate\Support\ServiceProvider;
use Laravel\Passkeys\Passkeys;

it('publishes only OIDC-owned migrations under the oidc migrations tag', function () {
    $publishPaths = ServiceProvider::pathsToPublish(OidcServiceProvider::class, 'oidc-migrations');

    $sourcePaths = array_map(realpath(...), array_keys($publishPaths));

    expect($sourcePaths)
        ->toBe([realpath(dirname(__DIR__).'/database/migrations')])
        ->not->toContain(realpath(Passkeys::migrationPath()));
});

it('publishes OIDC and passkeys migrations once and migrates a fresh database', function () {
    $temporaryPath = sys_get_temp_dir().'/laravel-oidc-publish-'.bin2hex(random_bytes(8));
    $migrationPath = $temporaryPath.'/migrations';
    $databasePath = $temporaryPath.'/database.sqlite';

    File::ensureDirectoryExists($migrationPath);
    File::put($databasePath, '');

    $oidcPublishPaths = ServiceProvider::$publishGroups['oidc-migrations'];
    $passkeysPublishPaths = ServiceProvider::$publishGroups['passkeys-migrations'];

    try {
        ServiceProvider::$publishGroups['oidc-migrations'] = array_fill_keys(
            array_keys($oidcPublishPaths),
            $migrationPath,
        );
        ServiceProvider::$publishGroups['passkeys-migrations'] = array_fill_keys(
            array_keys($passkeysPublishPaths),
            $migrationPath,
        );

        config()->set('database.connections.published', [
            ...config('database.connections.sqlite'),
            'database' => $databasePath,
        ]);

        $this->artisan('vendor:publish', ['--tag' => 'oidc-migrations'])->assertSuccessful();
        $this->artisan('vendor:publish', ['--tag' => 'passkeys-migrations'])->assertSuccessful();

        $this->artisan('migrate:fresh', [
            '--database' => 'published',
            '--path' => [
                dirname(__DIR__).'/vendor/orchestra/testbench-core/laravel/migrations',
                dirname(__DIR__).'/vendor/laravel/passport/database/migrations',
                $migrationPath,
            ],
            '--realpath' => true,
        ])->assertSuccessful();

        $passkeysMigrations = collect(File::files($migrationPath))
            ->filter(fn (SplFileInfo $file): bool => str_ends_with($file->getFilename(), '_create_passkeys_table.php'));

        expect($passkeysMigrations)->toHaveCount(1);
    } finally {
        ServiceProvider::$publishGroups['oidc-migrations'] = $oidcPublishPaths;
        ServiceProvider::$publishGroups['passkeys-migrations'] = $passkeysPublishPaths;

        File::deleteDirectory($temporaryPath);
    }
});

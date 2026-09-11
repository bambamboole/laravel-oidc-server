<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tests;

use Bambamboole\LaravelOidc\Server\OidcServiceProvider;
use Laravel\Passkeys\PasskeysServiceProvider;
use Orchestra\Testbench\Attributes\WithConfig;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as BaseTestCase;

/**
 * Stands in for an application whose published `config/oidc.php` predates
 * providers the package has since shipped: it defines `social.providers` with
 * only its own entry and an overridden `google`. `defer: false` is what makes
 * this faithful — the value has to be in the repository before the provider
 * registers, the way a real config file is, or the merge under test never runs.
 */
#[WithConfig('oidc.social.providers', [
    'keycloak' => ['driver' => 'oidc', 'client_id' => 'kc'],
    'google' => ['driver' => 'google', 'client_id' => 'mine'],
], defer: false)]
class RegistryConfigMergeTest extends BaseTestCase
{
    use WithWorkbench;

    protected $enablesPackageDiscoveries = false;

    protected function getPackageProviders($app): array
    {
        return [
            PasskeysServiceProvider::class,
            OidcServiceProvider::class,
        ];
    }

    public function test_a_shipped_registry_entry_survives_a_partial_application_map(): void
    {
        $providers = config('oidc.social.providers');

        $this->assertArrayHasKey('apple', $providers);
        $this->assertArrayHasKey('github', $providers);
        $this->assertSame('apple', $providers['apple']['driver']);
    }

    public function test_the_application_entry_wins_whole_and_is_never_patched_into(): void
    {
        $providers = config('oidc.social.providers');

        $this->assertSame(['driver' => 'google', 'client_id' => 'mine'], $providers['google']);
        $this->assertSame(['driver' => 'oidc', 'client_id' => 'kc'], $providers['keycloak']);
    }

    public function test_the_group_holding_a_registry_keeps_its_other_keys(): void
    {
        $this->assertTrue(config('oidc.social.link_by_verified_email'));
        $this->assertTrue(config('oidc.social.auto_provision'));
    }
}

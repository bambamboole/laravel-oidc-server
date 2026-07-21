<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Social;

use Bambamboole\LaravelOidc\Auth\Social\Contracts\SocialProvider;
use Closure;

/**
 * Resolves social providers from `oidc.social.providers` config. A provider is
 * active only when its client_id is configured; `extend()` registers custom
 * driver factories keyed by driver name.
 */
class SocialProviderRegistry
{
    /**
     * @var array<string, class-string<SocialProvider>>
     */
    private const array DRIVERS = [
        'oidc' => OidcProvider::class,
        'google' => GoogleProvider::class,
        'apple' => AppleProvider::class,
        'github' => GitHubProvider::class,
    ];

    /**
     * @var array<string, Closure(string, array<string, mixed>): SocialProvider>
     */
    private array $customCreators = [];

    /**
     * @param  Closure(string, array<string, mixed>): SocialProvider  $creator
     */
    public function extend(string $driver, Closure $creator): void
    {
        $this->customCreators[$driver] = $creator;
    }

    public function get(string $key): ?SocialProvider
    {
        $config = config("oidc.social.providers.{$key}");

        if (! is_array($config) || ! is_string($config['client_id'] ?? null) || $config['client_id'] === '') {
            return null;
        }

        $driver = is_string($config['driver'] ?? null) ? $config['driver'] : $key;

        if (isset($this->customCreators[$driver])) {
            return ($this->customCreators[$driver])($key, $config);
        }

        $class = self::DRIVERS[$driver] ?? null;

        return $class === null ? null : new $class($key, $config);
    }

    /**
     * @return array<string, SocialProvider>
     */
    public function enabled(): array
    {
        $providers = [];

        foreach (array_keys((array) config('oidc.social.providers', [])) as $key) {
            $provider = $this->get((string) $key);

            if ($provider !== null) {
                $providers[(string) $key] = $provider;
            }
        }

        return $providers;
    }
}

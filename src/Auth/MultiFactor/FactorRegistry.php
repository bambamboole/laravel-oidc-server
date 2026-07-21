<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor;

use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\FactorProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use LogicException;

class FactorRegistry
{
    /**
     * @var array<string, FactorProvider>
     */
    private array $providers = [];

    public function register(FactorProvider $provider): void
    {
        if (isset($this->providers[$provider->key()])) {
            throw new LogicException("A factor provider is already registered for [{$provider->key()}].");
        }

        $this->providers[$provider->key()] = $provider;
    }

    public function get(string $key): FactorProvider
    {
        return $this->providers[$key]
            ?? throw new LogicException("No factor provider is registered for [{$key}].");
    }

    /**
     * @return array<string, FactorProvider>
     */
    public function providers(): array
    {
        return $this->providers;
    }

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        $enrollments = [];

        foreach ($this->providers as $provider) {
            array_push($enrollments, ...$provider->enrollments($user));
        }

        return $enrollments;
    }

    /**
     * @param  list<string>|null  $providerKeys
     * @return list<FactorEnrollment>
     */
    public function challengeableEnrollments(Authenticatable $user, ?array $providerKeys = null): array
    {
        $enrollments = [];

        foreach ($this->providers as $provider) {
            if ($provider->isBackup() || ($providerKeys !== null && ! in_array($provider->key(), $providerKeys, true))) {
                continue;
            }

            foreach ($provider->enrollments($user) as $enrollment) {
                if ($enrollment->confirmedAt !== null) {
                    $enrollments[] = $enrollment;
                }
            }
        }

        return $enrollments;
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\FactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Data\EnrollmentOption;
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
     * The provider for $key when it supports enrollment through the generic
     * endpoints, null for an unknown key or a provider that cannot be enrolled
     * in at all.
     */
    public function enrollable(string $key): ?EnrollableFactorProvider
    {
        $provider = $this->providers[$key] ?? null;

        return $provider instanceof EnrollableFactorProvider ? $provider : null;
    }

    /**
     * @return array<string, FactorProvider>
     */
    public function providers(): array
    {
        return $this->providers;
    }

    /**
     * Every way a user could add a factor, ordered for display. Backup
     * providers stay out: recovery codes are backfilled, never picked.
     *
     * @return list<EnrollmentOption>
     */
    public function enrollmentOptions(): array
    {
        $options = [];

        foreach ($this->providers as $provider) {
            if ($provider->isBackup() || ! $provider instanceof EnrollableFactorProvider) {
                continue;
            }

            array_push($options, ...$provider->enrollmentOptions());
        }

        usort($options, static fn (EnrollmentOption $a, EnrollmentOption $b): int => [$a->sortOrder, $a->id] <=> [$b->sortOrder, $b->id]);

        return $options;
    }

    public function enrollmentOption(string $id): ?EnrollmentOption
    {
        foreach ($this->enrollmentOptions() as $option) {
            if ($option->id === $id) {
                return $option;
            }
        }

        return null;
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
     * One of the user's enrollments — pending or confirmed — by provider and id.
     * The single lookup every revoke/confirm surface should use, so ownership is
     * proven the same way everywhere.
     */
    public function findEnrollment(Authenticatable $user, string $providerKey, string $id): ?FactorEnrollment
    {
        $provider = $this->providers[$providerKey] ?? null;

        if ($provider === null) {
            return null;
        }

        foreach ($provider->enrollments($user) as $enrollment) {
            if ($enrollment->id === $id) {
                return $enrollment;
            }
        }

        return null;
    }

    /**
     * The enrollments a login challenge may be satisfied with, limited to the
     * providers the host opted into via `oidc.auth.two_factor.challenge_providers`.
     *
     * @return list<FactorEnrollment>
     */
    public function configuredChallengeableEnrollments(Authenticatable $user): array
    {
        $providerKeys = array_values(array_filter(
            (array) config('oidc.auth.two_factor.challenge_providers', ['totp']),
            is_string(...),
        ));

        return $this->challengeableEnrollments($user, $providerKeys);
    }

    /**
     * Whether the user has at least one confirmed, challengeable enrollment —
     * the "does this user have 2FA?" check.
     */
    public function hasChallengeableFactors(Authenticatable $user): bool
    {
        return $this->challengeableEnrollments($user) !== [];
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

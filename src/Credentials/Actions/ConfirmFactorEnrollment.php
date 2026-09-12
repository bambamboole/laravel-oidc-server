<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Credentials\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\EnrollmentPolicy;
use Bambamboole\LaravelOidc\Server\Credentials\Events\FactorConfirmed;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Illuminate\Contracts\Auth\Authenticatable;

readonly class ConfirmFactorEnrollment
{
    public function __construct(
        protected EnrollmentPolicy $policy,
    ) {}

    /**
     * @param  array<string, mixed>  $proof
     */
    public function __invoke(
        Authenticatable $user,
        EnrollableFactorProvider $provider,
        FactorEnrollment $enrollment,
        array $proof,
    ): bool {
        if (! $provider->confirmEnrollment($user, $enrollment, $proof)) {
            return false;
        }

        $this->policy->factorConfirmed($user);

        event(new FactorConfirmed((string) $user->getAuthIdentifier(), $provider->key(), $enrollment->id));

        return true;
    }
}

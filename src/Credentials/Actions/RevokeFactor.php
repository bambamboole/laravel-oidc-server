<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Credentials\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\EnrollmentPolicy;
use Bambamboole\LaravelOidc\Server\Credentials\Events\FactorRevoked;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Illuminate\Contracts\Auth\Authenticatable;

final readonly class RevokeFactor
{
    public function __construct(
        private EnrollmentPolicy $policy,
    ) {}

    public function __invoke(Authenticatable $user, EnrollableFactorProvider $provider, FactorEnrollment $enrollment): void
    {
        $provider->revoke($user, $enrollment);
        $this->policy->factorRevoked($user);

        event(new FactorRevoked((string) $user->getAuthIdentifier(), $provider->key(), $enrollment->id));
    }
}

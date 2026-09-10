<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Credentials\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\Data\EnrollmentOption;
use Bambamboole\LaravelOidc\Server\Credentials\Events\FactorEnrollmentStarted;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Illuminate\Contracts\Auth\Authenticatable;

final readonly class EnrollFactor
{
    public function __invoke(
        Authenticatable $user,
        EnrollableFactorProvider $provider,
        ?EnrollmentOption $option = null,
        ?string $name = null,
    ): FactorEnrollment {
        $enrollment = $provider->beginEnrollment($user, $option, $name);

        event(new FactorEnrollmentStarted((string) $user->getAuthIdentifier(), $provider->key(), $enrollment->id));

        return $enrollment;
    }
}

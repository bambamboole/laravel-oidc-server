<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Data\EnrollmentOption;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorEnrollment;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A factor type users can enroll in through the generic two-factor
 * enrollment endpoints. beginEnrollment() returns a pending enrollment whose
 * metadata carries the provider-specific setup payload (e.g. the TOTP
 * secret); confirmEnrollment() proves the user completed setup.
 */
interface EnrollableFactorProvider extends FactorProvider, OffersEnrollment
{
    /**
     * $option is the entry from {@see OffersEnrollment::enrollmentOptions()} the
     * user picked; null falls back to the provider's own default.
     */
    public function beginEnrollment(Authenticatable $user, ?EnrollmentOption $option = null, ?string $name = null): FactorEnrollment;

    /**
     * @param  array<string, mixed>  $input
     */
    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, array $input): bool;

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void;
}

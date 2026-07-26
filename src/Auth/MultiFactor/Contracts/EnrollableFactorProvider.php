<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorResponse;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A factor type users can enroll in through the generic two-factor
 * enrollment endpoints. beginEnrollment() returns a pending enrollment whose
 * metadata carries the provider-specific setup payload (e.g. the TOTP
 * secret); confirmEnrollment() proves the user completed setup.
 */
interface EnrollableFactorProvider extends FactorProvider
{
    public function beginEnrollment(Authenticatable $user, ?string $name = null): FactorEnrollment;

    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, FactorResponse $response): bool;

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void;
}

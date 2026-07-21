<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts;

use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorChallenge;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorEnrollment;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorResponse;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorVerification;
use Illuminate\Contracts\Auth\Authenticatable;

interface FactorProvider
{
    public function key(): string;

    public function isBackup(): bool;

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array;

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge;

    public function verify(Authenticatable $user, FactorChallenge $challenge, FactorResponse $response): FactorVerification;
}

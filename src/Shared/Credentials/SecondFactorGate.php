<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * What the login sequence needs to know about second factors: whether the
 * user can be challenged at all, and how to park the login until they are.
 */
interface SecondFactorGate
{
    public function hasChallengeableFactors(Authenticatable $user): bool;

    /**
     * Stores the pending challenge for the current session; the challenge
     * endpoints complete the login once the factor is verified.
     */
    public function beginChallenge(Authenticatable $user, bool $remember): void;
}

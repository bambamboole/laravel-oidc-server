<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Authentication;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/**
 * The single post-authentication sequence every interactive login must pass
 * through: post-login policy, claim buffering, second-factor gating, guard
 * login. Calling guard->login() directly bypasses the policy and leaves the
 * authentication methods untracked.
 */
interface LoginFinalizer
{
    /**
     * $challengeEnrolledFactors controls whether an enrolled second factor is
     * challenged automatically; a login method that already verified the
     * device (passkeys) passes false. An explicit requireMfa() from the
     * pipeline still forces the challenge.
     */
    public function finalize(
        Request $request,
        Authenticatable $user,
        string $method,
        bool $remember = false,
        bool $challengeEnrolledFactors = true,
    ): LoginOutcome;

    /**
     * The tail of finalize() for a flow that finished its own verification
     * afterwards, such as a second-factor challenge: guard login, session
     * regeneration and the LoginSucceeded event.
     */
    public function complete(Request $request, Authenticatable $user, bool $remember = false): void;
}

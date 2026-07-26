<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Pipeline\InteractiveLoginFinalizer;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginOutcome;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyLoginResponse;
use Laravel\Passkeys\Exceptions\InvalidPasskeyException;
use Laravel\Passkeys\Http\Requests\PasskeyVerificationRequest;
use Laravel\Passkeys\Passkeys;

/**
 * Replaces the vendor PasskeyLoginController for the login ceremony: the
 * credential check is the vendor's, but the login itself must finalize
 * through the shared post-login sequence so the postLogin policy applies and
 * amr records the passkey ('swk') method.
 */
class PasskeyAuthenticatedSessionController
{
    public function __construct(
        private readonly InteractiveLoginFinalizer $finalizer,
    ) {}

    public function store(
        PasskeyVerificationRequest $request,
        VerifyPasskey $verify,
    ): PasskeyLoginResponse|JsonResponse|RedirectResponse {
        $passkey = $verify($request->credential(), $request->verificationOptions());

        if (! Passkeys::allowsLogin($request, $passkey)) {
            throw InvalidPasskeyException::make('Unable to sign in with this account.');
        }

        $outcome = $this->finalizer->finalize(
            $request,
            $passkey->user,
            'swk',
            $request->remember(),
            challengeEnrolledFactors: false,
        );

        return match ($outcome) {
            LoginOutcome::Denied => throw InvalidPasskeyException::make('Unable to sign in with this account.'),
            LoginOutcome::MfaChallenge => $request->wantsJson()
                ? new JsonResponse(['two_factor' => true])
                : redirect()->route(Handler::TwoFactorLogin->value),
            LoginOutcome::LoggedIn => app(PasskeyLoginResponse::class),
        };
    }
}

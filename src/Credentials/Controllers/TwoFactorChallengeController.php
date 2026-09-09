<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Credentials\Actions\VerifyFactorChallenge;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Credentials\FactorRegistry;
use Bambamboole\LaravelOidc\Server\Credentials\PendingMfaChallenge;
use Bambamboole\LaravelOidc\Server\Credentials\Views\TwoFactorChallengePrompt;
use Bambamboole\LaravelOidc\Server\Credentials\Views\TwoFactorChallengeView;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class TwoFactorChallengeController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly AuthSessionState $sessionState,
        private readonly VerifyFactorChallenge $verifyChallenge,
    ) {}

    /**
     * TwoFactorChallengeView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function create(Request $request): Responsable|RedirectResponse|Response
    {
        $pending = PendingMfaChallenge::find();
        $user = $pending === null ? null : $this->challengedUser($pending);

        if ($pending === null || $user === null) {
            return redirect()->route('identity.login');
        }

        return app(TwoFactorChallengeView::class)->respond(new TwoFactorChallengePrompt(
            factor: $pending->factor,
            availableFactors: $this->factors->configuredChallengeableEnrollments($user),
            factorId: $pending->factorId,
        ), $request);
    }

    /**
     * Switches the pending challenge to another of the user's challengeable
     * factors — the provider's first enrollment, or a specific one when an
     * enrollment id is given. Matching against
     * configuredChallengeableEnrollments() validates ownership, confirmation,
     * and the challenge-provider allow-list in one step; an unknown or
     * unenrolled provider or enrollment is silently ignored.
     */
    public function selectFactor(Request $request, string $provider, ?string $enrollment = null): RedirectResponse
    {
        $pending = PendingMfaChallenge::find();
        $user = $pending === null ? null : $this->challengedUser($pending);

        if ($pending === null || $user === null) {
            return redirect()->route('identity.login');
        }

        foreach ($this->factors->configuredChallengeableEnrollments($user) as $available) {
            if ($available->providerKey === $provider && ($enrollment === null || $available->id === $enrollment)) {
                (new PendingMfaChallenge(
                    userId: $pending->userId,
                    remember: $pending->remember,
                    factor: $available->providerKey,
                    factorId: $available->id,
                ))->store();

                break;
            }
        }

        return redirect()->route('identity.two-factor.login');
    }

    /**
     * Issues the pending factor's challenge: the private half is persisted in
     * the session for store() to verify against, the public half (e.g. the
     * WebAuthn request options) goes to the browser. Challenge issuance and
     * verification are separate requests by design — options generated in the
     * same request as the verification can never match a real assertion.
     */
    public function options(Request $request): JsonResponse
    {
        $pending = PendingMfaChallenge::find();
        $user = $pending === null ? null : $this->challengedUser($pending);

        if ($pending === null || $user === null) {
            return new JsonResponse(['message' => 'No pending two-factor challenge.'], 401);
        }

        $enrollment = $this->pendingEnrollment($user, $pending->factor, $pending->factorId);

        if (! $enrollment instanceof FactorEnrollment) {
            return new JsonResponse(['message' => 'No pending two-factor challenge.'], 401);
        }

        $challenge = $this->factors->get($pending->factor)->beginChallenge($user, $enrollment);

        PendingMfaChallenge::storeChallengeState($challenge->privateState);

        return new JsonResponse($challenge->publicData);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $request->validate([
            'code' => ['nullable', 'string'],
            'recovery_code' => ['nullable', 'string'],
            'credential' => ['nullable', 'array'],
        ]);

        $pending = PendingMfaChallenge::find();
        $user = $pending === null ? null : $this->challengedUser($pending);

        if ($pending === null || $user === null) {
            return redirect()->route('identity.login');
        }

        $usesRecoveryCode = $request->filled('recovery_code');
        $verification = ($this->verifyChallenge)($user, $pending, $request->only('code', 'recovery_code', 'credential'));

        if ($verification === null) {
            $field = $usesRecoveryCode ? 'recovery_code' : 'code';

            throw ValidationException::withMessages([$field => __('The provided two factor authentication code was invalid.')]);
        }

        $this->sessionState->add(...$verification->amr);

        PendingMfaChallenge::forget();
        $this->sessionGuard()->login($user, $pending->remember);

        if ($request->hasSession()) {
            $request->session()->regenerate();
        }

        if ($request->wantsJson()) {
            // A WebAuthn submit comes from the passkey ceremony script, which
            // navigates via the returned redirect target.
            return $request->filled('credential')
                ? new JsonResponse(['redirect' => redirect()->intended($this->homeUrl())->getTargetUrl()])
                : new JsonResponse('', 204);
        }

        return redirect()->intended($this->homeUrl());
    }

    private function challengedUser(PendingMfaChallenge $pending): ?Authenticatable
    {
        return $this->sessionGuard()->getProvider()->retrieveById($pending->userId);
    }

    private function pendingEnrollment(Authenticatable $user, string $providerKey, string $id): ?FactorEnrollment
    {
        foreach ($this->factors->get($providerKey)->enrollments($user) as $enrollment) {
            if ($id === '' || $enrollment->id === $id) {
                return $enrollment;
            }
        }

        return null;
    }
}

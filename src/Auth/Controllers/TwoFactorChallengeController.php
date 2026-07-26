<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Controllers;

use Bambamboole\LaravelOidc\Server\Auth\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorChallenge;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorResponse;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\PendingMfaChallenge;
use Bambamboole\LaravelOidc\Server\Auth\Views\TwoFactorChallengePrompt;
use Bambamboole\LaravelOidc\Server\Auth\Views\TwoFactorChallengeView;
use Bambamboole\LaravelOidc\Server\Routing\Handler;
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
    ) {}

    /**
     * TwoFactorChallengeView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function create(Request $request): Responsable|RedirectResponse|Response
    {
        $pending = PendingMfaChallenge::find();

        if ($pending === null || $this->challengedUser($pending) === null) {
            return redirect()->route(Handler::Login->value);
        }

        return app(TwoFactorChallengeView::class)->respond(new TwoFactorChallengePrompt(
            factor: $pending->factor,
        ), $request);
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
            return redirect()->route(Handler::Login->value);
        }

        $usesRecoveryCode = $request->filled('recovery_code');
        $providerKey = $usesRecoveryCode ? 'recovery_code' : $pending->factor;
        $provider = $this->factors->get($providerKey);
        $enrollment = $usesRecoveryCode
            ? $provider->enrollments($user)[0] ?? null
            : $this->pendingEnrollment($user, $providerKey, $pending->factorId);

        if (! $enrollment instanceof FactorEnrollment) {
            throw ValidationException::withMessages(['code' => __('The provided two factor authentication code was invalid.')]);
        }

        $challenge = new FactorChallenge($enrollment, privateState: PendingMfaChallenge::pullChallengeState());
        $verification = $provider->verify($user, $challenge, new FactorResponse($request->only('code', 'recovery_code', 'credential')));

        if (! $verification->verified) {
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

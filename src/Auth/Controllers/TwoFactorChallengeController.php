<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorEnrollment;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorResponse;
use Bambamboole\LaravelOidc\Auth\Views\TwoFactorChallengePrompt;
use Bambamboole\LaravelOidc\Auth\Views\TwoFactorChallengeView;
use Bambamboole\LaravelOidc\Routing\Handler;
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
        private readonly AuthenticationMethods $context,
    ) {}

    /**
     * TwoFactorChallengeView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function create(Request $request): Responsable|RedirectResponse|Response
    {
        if ($this->challengedUser($request) === null) {
            return redirect()->route(Handler::Login->value);
        }

        return app(TwoFactorChallengeView::class)->respond(new TwoFactorChallengePrompt, $request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $request->validate([
            'code' => ['nullable', 'string'],
            'recovery_code' => ['nullable', 'string'],
        ]);

        $user = $this->challengedUser($request);

        if ($user === null) {
            return redirect()->route(Handler::Login->value);
        }

        $usesRecoveryCode = $request->filled('recovery_code');
        $providerKey = $usesRecoveryCode ? 'recovery_code' : (string) $request->session()->get('login.factor', 'totp');
        $provider = $this->factors->get($providerKey);
        $enrollment = $usesRecoveryCode
            ? $provider->enrollments($user)[0] ?? null
            : $this->pendingEnrollment($user, $providerKey, (string) $request->session()->get('login.factor_id'));

        if (! $enrollment instanceof FactorEnrollment) {
            throw ValidationException::withMessages(['code' => __('The provided two factor authentication code was invalid.')]);
        }

        $challenge = $provider->beginChallenge($user, $enrollment);
        $verification = $provider->verify($user, $challenge, new FactorResponse($request->only('code', 'recovery_code')));

        if (! $verification->verified) {
            $field = $usesRecoveryCode ? 'recovery_code' : 'code';

            throw ValidationException::withMessages([$field => __('The provided two factor authentication code was invalid.')]);
        }

        $this->context->add(...$verification->amr);

        $remember = (bool) $request->session()->pull('login.remember', false);
        $request->session()->forget(['login.id', 'login.factor', 'login.factor_id']);
        $this->sessionGuard()->login($user, $remember);

        if ($request->hasSession()) {
            $request->session()->regenerate();
        }

        if ($request->wantsJson()) {
            return new JsonResponse('', 204);
        }

        return redirect()->intended($this->homeUrl());
    }

    private function challengedUser(Request $request): ?Authenticatable
    {
        $id = $request->session()->get('login.id');

        return $id === null ? null : $this->sessionGuard()->getProvider()->retrieveById($id);
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

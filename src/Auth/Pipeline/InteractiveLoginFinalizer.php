<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Pipeline;

use Bambamboole\LaravelOidc\Server\Auth\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesPendingAuthorization;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\PendingMfaChallenge;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\Contracts\DeviceRecognizer;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * The single post-authentication sequence for interactive logins: postLogin
 * policy, claim buffering, second-factor gating, guard login. Every path that
 * authenticates a user interactively (password, social, registration,
 * password reset, passkey) must finalize through here — a path that calls
 * guard->login() directly bypasses the policy and leaves amr untracked.
 */
final class InteractiveLoginFinalizer
{
    use ResolvesIdentityGuard;
    use ResolvesPendingAuthorization;

    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly AuthSessionState $sessionState,
        private readonly PostLoginPipeline $pipeline,
        private readonly DeviceRecognizer $deviceRecognizer,
    ) {}

    /**
     * $challengeEnrolledFactors controls whether an enrolled second factor is
     * challenged automatically. Passkey logins pass false — the ceremony
     * already verified user presence on a bound device — but an explicit
     * requireMfa() from the pipeline still forces the challenge.
     */
    public function finalize(
        Request $request,
        Authenticatable $user,
        string $method,
        bool $remember = false,
        bool $challengeEnrolledFactors = true,
    ): LoginOutcome {
        $this->sessionState->start($method);

        $api = $this->pipeline->run(new LoginEvent(
            user: $user,
            client: $this->pendingClient($request),
            scopes: $this->pendingScopes($request),
            requestedAcrValues: $this->sessionState->requestedAcrValues(),
            ip: $request->ip(),
            userAgent: $request->userAgent(),
            amr: [$method],
            authTime: null,
            recognizer: $this->deviceRecognizer,
            request: $request,
        ));

        if ($api->isDenied()) {
            Log::warning('oidc: login denied by postLogin', ['method' => $method, 'reason' => $api->denyReason()]);
            $this->sessionState->forget();

            return LoginOutcome::Denied;
        }

        $this->sessionState->putClaims($api->idTokenClaims(), $api->accessTokenClaims());

        $enrollments = $this->factors->challengeableEnrollments($user, $this->challengeProviders());

        if ($api->mfaRequired() && $enrollments === []) {
            Log::warning('oidc: login denied, MFA required but no challengeable factor', ['method' => $method]);
            $this->sessionState->forget();

            return LoginOutcome::Denied;
        }

        if ($enrollments !== [] && ($challengeEnrolledFactors || $api->mfaRequired())) {
            (new PendingMfaChallenge(
                userId: $user->getAuthIdentifier(),
                remember: $remember,
                factor: $enrollments[0]->providerKey,
                factorId: $enrollments[0]->id,
            ))->store();

            return LoginOutcome::MfaChallenge;
        }

        $this->sessionGuard()->login($user, $remember);

        if ($request->hasSession()) {
            $request->session()->regenerate();
        }

        return LoginOutcome::LoggedIn;
    }

    /**
     * @return list<string>
     */
    private function challengeProviders(): array
    {
        return array_values(array_filter(
            (array) config('oidc.auth.two_factor.challenge_providers', ['totp']),
            is_string(...),
        ));
    }
}

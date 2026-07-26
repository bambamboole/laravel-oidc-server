<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Pipeline;

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesPendingAuthorization;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Contracts\DeviceRecognizer;
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
        private readonly AuthenticationMethods $context,
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
        $this->context->start($method);

        $api = $this->pipeline->run(new LoginEvent(
            user: $user,
            client: $this->pendingClient($request),
            scopes: $this->pendingScopes($request),
            requestedAcrValues: [],
            ip: $request->ip(),
            userAgent: $request->userAgent(),
            amr: [$method],
            authTime: null,
            recognizer: $this->deviceRecognizer,
            request: $request,
        ));

        if ($api->isDenied()) {
            Log::warning('oidc: login denied by postLogin', ['method' => $method, 'reason' => $api->denyReason()]);
            $this->context->forget();

            return LoginOutcome::Denied;
        }

        $request->session()->put('oidc.id_token_claims', $api->idTokenClaims());
        $request->session()->put('oidc.access_token_claims', $api->accessTokenClaims());

        $enrollments = $this->factors->challengeableEnrollments($user, $this->challengeProviders());

        if ($api->mfaRequired() && $enrollments === []) {
            Log::warning('oidc: login denied, MFA required but no challengeable factor', ['method' => $method]);
            $this->context->forget();

            return LoginOutcome::Denied;
        }

        if ($enrollments !== [] && ($challengeEnrolledFactors || $api->mfaRequired())) {
            $request->session()->put([
                'login.id' => $user->getAuthIdentifier(),
                'login.remember' => $remember,
                'login.factor' => $enrollments[0]->providerKey,
                'login.factor_id' => $enrollments[0]->id,
            ]);

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

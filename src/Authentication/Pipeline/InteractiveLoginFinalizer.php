<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Pipeline;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\DeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\LoginFinalizer;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\LoginOutcome;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\SecondFactorGate;
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
final class InteractiveLoginFinalizer implements LoginFinalizer
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly SecondFactorGate $secondFactor,
        private readonly AuthSessionState $sessionState,
        private readonly PostLoginPipeline $pipeline,
        private readonly DeviceRecognizer $deviceRecognizer,
        private readonly Auditor $auditor,
        private readonly PendingAuthorization $pending,
        private readonly ClientRepository $clients,
    ) {}

    /** The active client behind the pending authorization request, if any. */
    private function pendingClient(Request $request): ?Client
    {
        $clientId = $this->pending->clientId($request);

        return $clientId === null ? null : $this->clients->findActive($clientId);
    }

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
            scopes: $this->pending->scopes($request),
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
            $this->auditor->log(AuditEventType::LoginFailed, userId: (string) $user->getAuthIdentifier(), context: array_filter([
                'method' => $method,
                'reason' => 'policy_denied',
                'deny_reason' => $api->denyReason(),
            ]));
            $this->sessionState->forget();

            return LoginOutcome::Denied;
        }

        $this->sessionState->putClaims($api->idTokenClaims(), $api->accessTokenClaims());

        $challengeable = $this->secondFactor->hasChallengeableFactors($user);

        if ($api->mfaRequired() && ! $challengeable) {
            Log::warning('oidc: login denied, MFA required but no challengeable factor', ['method' => $method]);
            $this->auditor->log(AuditEventType::LoginFailed, userId: (string) $user->getAuthIdentifier(), context: [
                'method' => $method,
                'reason' => 'mfa_required_without_factor',
            ]);
            $this->sessionState->forget();

            return LoginOutcome::Denied;
        }

        if ($challengeable && ($challengeEnrolledFactors || $api->mfaRequired())) {
            $this->secondFactor->beginChallenge($user, $remember);

            return LoginOutcome::MfaChallenge;
        }

        $this->sessionGuard()->login($user, $remember);

        if ($request->hasSession()) {
            $request->session()->regenerate();
        }

        return LoginOutcome::LoggedIn;
    }
}

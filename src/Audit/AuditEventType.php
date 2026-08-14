<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

enum AuditEventType: string
{
    case LoginSucceeded = 'auth.login.succeeded';
    case LoginFailed = 'auth.login.failed';
    case Logout = 'auth.logout';
    case MfaChallengeSucceeded = 'auth.mfa.challenge_succeeded';
    case MfaChallengeFailed = 'auth.mfa.challenge_failed';
    case RecoveryCodeUsed = 'auth.mfa.recovery_code_used';
    case FactorEnrollmentStarted = 'auth.mfa.factor_enrollment_started';
    case FactorConfirmed = 'auth.mfa.factor_confirmed';
    case FactorRevoked = 'auth.mfa.factor_revoked';
    case UserRegistered = 'auth.registration.succeeded';
    case PasswordReset = 'auth.password.reset';

    case ConsentApproved = 'oauth.consent.approved';
    case ConsentDenied = 'oauth.consent.denied';
    case TokenIssued = 'oauth.token.issued';
    case TokenIssuanceFailed = 'oauth.token.failed';
    case TokenRevoked = 'oauth.token.revoked';
    case ClientAuthenticationFailed = 'oauth.client_auth.failed';

    case ClientRegistered = 'admin.client.registered';
    case ClientProvisioned = 'admin.client.provisioned';
    case KeysRotated = 'admin.keys.rotated';

    public function category(): string
    {
        return explode('.', $this->value)[0];
    }

    public function isFailure(): bool
    {
        return match ($this) {
            self::LoginFailed,
            self::MfaChallengeFailed,
            self::ConsentDenied,
            self::TokenIssuanceFailed,
            self::ClientAuthenticationFailed => true,
            default => false,
        };
    }
}

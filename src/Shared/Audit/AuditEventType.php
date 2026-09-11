<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Audit;

/**
 * The types the server package's own audit events carry. The value is a dotted
 * string whose first segment is the category (auth, oauth, admin); a host app
 * raising its own audit events brings its own enum or plain strings.
 */
enum AuditEventType: string
{
    case LoginSucceeded = 'auth.login.succeeded';
    case LoginFailed = 'auth.login.failed';
    case LoggedOut = 'auth.logout';
    case UserRegistered = 'auth.registration.succeeded';
    case PasswordReset = 'auth.password.reset';
    case PasswordChanged = 'auth.password.changed';
    case MfaChallengeSucceeded = 'auth.mfa.challenge_succeeded';
    case MfaChallengeFailed = 'auth.mfa.challenge_failed';
    case RecoveryCodeUsed = 'auth.mfa.recovery_code_used';
    case FactorEnrollmentStarted = 'auth.mfa.factor_enrollment_started';
    case FactorConfirmed = 'auth.mfa.factor_confirmed';
    case FactorRevoked = 'auth.mfa.factor_revoked';
    case ConsentApproved = 'oauth.consent.approved';
    case ConsentDenied = 'oauth.consent.denied';
    case TokenIssued = 'oauth.token.issued';
    case TokenIssuanceFailed = 'oauth.token.failed';
    case TokenRevoked = 'oauth.token.revoked';
    case ClientAuthenticationFailed = 'oauth.client_auth.failed';
    case ClientRegistered = 'admin.client.registered';
    case ClientProvisioned = 'admin.client.provisioned';
    case KeysRotated = 'admin.keys.rotated';
}

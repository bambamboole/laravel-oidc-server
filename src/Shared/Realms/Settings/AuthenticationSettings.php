<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Realms\Settings;

/**
 * The realm's rules for an interactive login: which methods it accepts, how
 * hard it insists on a second factor, and whether a confirmed email address
 * is a precondition for a session.
 *
 * There is deliberately no list of required actions here. Every action the
 * package derives has its own setting already — `emailVerificationRequired`,
 * `$mfa`, and `CredentialSettings::$password->maxAgeDays` — so a second
 * switch would only be a way for the two to disagree.
 */
final readonly class AuthenticationSettings
{
    /**
     * @param  list<LoginMethod>  $methods  the login methods the realm accepts
     * @param  MfaRequirement  $mfa  how hard the realm insists on a second factor
     * @param  bool  $emailVerificationRequired  whether an unverified address blocks the login
     */
    public function __construct(
        public array $methods = [LoginMethod::Password, LoginMethod::Passkey, LoginMethod::Social],
        public MfaRequirement $mfa = MfaRequirement::IfEnrolled,
        public bool $emailVerificationRequired = false,
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            methods: LoginMethod::listFromConfig((array) config('oidc.authentication.methods', ['password', 'passkey', 'social'])),
            mfa: MfaRequirement::fromConfig(config('oidc.authentication.mfa')),
            emailVerificationRequired: (bool) config('oidc.authentication.email_verification_required', false),
        );
    }

    public function allows(LoginMethod $method): bool
    {
        return in_array($method, $this->methods, true);
    }
}

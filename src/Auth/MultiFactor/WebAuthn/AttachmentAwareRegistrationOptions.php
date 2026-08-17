<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor\WebAuthn;

use Laravel\Passkeys\Actions\GenerateRegistrationOptions;
use Webauthn\AuthenticatorSelectionCriteria;

/**
 * Registration options that ask for a specific authenticator attachment.
 *
 * The shipped action hardcodes `no preference`, which leaves the browser to
 * offer its own "Touch ID / security key / phone" chooser. Naming the
 * attachment sends the user straight to the one they picked. Only the
 * attachment changes — resident-key and user-verification requirements stay
 * whatever the parent decided.
 */
final class AttachmentAwareRegistrationOptions extends GenerateRegistrationOptions
{
    public function __construct(private readonly string $attachment) {}

    #[\Override]
    public function authenticatorSelection(): AuthenticatorSelectionCriteria
    {
        $selection = parent::authenticatorSelection();

        return AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: $this->attachment,
            userVerification: $selection->userVerification,
            residentKey: $selection->residentKey,
        );
    }
}

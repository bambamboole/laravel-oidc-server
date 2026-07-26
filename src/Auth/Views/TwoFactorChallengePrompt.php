<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Views;

final readonly class TwoFactorChallengePrompt
{
    /**
     * $factor is the provider key of the pending second factor ('totp',
     * 'webauthn', ...) so the view can offer the matching input.
     */
    public function __construct(
        public ?string $factor = null,
    ) {}
}

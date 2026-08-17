<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Data;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Enums\FactorRole;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Enums\FactorSetupKind;

/**
 * One way to enroll in a factor. A provider may offer several: webauthn offers
 * `passkey` and `security_key`, which differ only in the authenticator
 * attachment the ceremony asks for — the resulting credential is the same kind
 * of thing and is verified identically, so they are options, not providers.
 *
 * Carries semantic identity only. Labels, descriptions, and icons belong to a
 * presentation layer, because the server package ships no translations and is
 * installable without the ui package.
 */
final readonly class EnrollmentOption
{
    /**
     * @param  string  $id  Globally unique across providers; the value a setup surface submits.
     * @param  array<string, mixed>  $hints  Provider-specific enrollment parameters.
     */
    public function __construct(
        public string $id,
        public string $providerKey,
        public FactorRole $role,
        public FactorSetupKind $setupKind,
        public bool $recommended = false,
        public int $sortOrder = 0,
        public array $hints = [],
    ) {}
}

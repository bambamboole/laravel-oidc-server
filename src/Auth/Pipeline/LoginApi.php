<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Pipeline;

use Bambamboole\LaravelOidc\Auth\ProtocolClaims;
use Illuminate\Support\Facades\Log;

class LoginApi extends AccessTokenApi
{
    private bool $mfaRequired = false;

    /** @var array<string, mixed> */
    private array $idTokenClaims = [];

    public function requireMfa(): void
    {
        $this->mfaRequired = true;
    }

    public function setIdTokenClaim(string $name, mixed $value): void
    {
        if (ProtocolClaims::isReserved($name)) {
            Log::warning("oidc: postLogin refused to set protected id_token claim [{$name}]");

            return;
        }

        $this->idTokenClaims[$name] = $value;
    }

    public function mfaRequired(): bool
    {
        return $this->mfaRequired;
    }

    /** @return array<string, mixed> */
    public function idTokenClaims(): array
    {
        return $this->idTokenClaims;
    }
}

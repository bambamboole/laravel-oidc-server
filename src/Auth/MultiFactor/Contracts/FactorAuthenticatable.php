<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts;

use Bambamboole\LaravelOidc\Auth\MultiFactor\Models\RecoveryCode;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Models\TotpFactor;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Laravel\Passkeys\Contracts\PasskeyUser;

interface FactorAuthenticatable extends PasskeyUser
{
    /**
     * @return MorphMany<TotpFactor, covariant Model>
     */
    public function totpFactors(): MorphMany;

    /**
     * @return MorphMany<RecoveryCode, covariant Model>
     */
    public function recoveryCodes(): MorphMany;
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor\Concerns;

use Bambamboole\LaravelOidc\Auth\MultiFactor\Models\RecoveryCode;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Models\TotpFactor;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Laravel\Passkeys\PasskeyAuthenticatable;

/**
 * @mixin Model
 */
trait HasAuthenticationFactors
{
    use PasskeyAuthenticatable;

    protected static function bootHasAuthenticationFactors(): void
    {
        static::deleting(function (Model $authenticatable): void {
            $authenticatable->morphMany(TotpFactor::class, 'authenticatable')->delete();
            $authenticatable->morphMany(RecoveryCode::class, 'authenticatable')->delete();
        });
    }

    /**
     * @return MorphMany<TotpFactor, $this>
     */
    public function totpFactors(): MorphMany
    {
        return $this->morphMany(TotpFactor::class, 'authenticatable');
    }

    /**
     * @return MorphMany<RecoveryCode, $this>
     */
    public function recoveryCodes(): MorphMany
    {
        return $this->morphMany(RecoveryCode::class, 'authenticatable');
    }
}

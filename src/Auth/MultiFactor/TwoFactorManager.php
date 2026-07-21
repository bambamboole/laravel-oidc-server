<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor;

use Bambamboole\LaravelOidc\Auth\MultiFactor\Concerns\InteractsWithFactorUser;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Models\TotpFactor;
use Illuminate\Contracts\Auth\Authenticatable;

class TwoFactorManager
{
    use InteractsWithFactorUser;

    public function __construct(
        private readonly TotpFactorProvider $totp,
        private readonly RecoveryCodeProvider $recoveryCodes,
    ) {}

    public function enable(Authenticatable $user, bool $force = false): TotpFactor
    {
        $user = $this->factorUser($user);
        $factor = $this->currentFactor($user);

        if ($factor instanceof TotpFactor && ! $force) {
            return $factor;
        }

        if ($force) {
            $this->disable($user);
        }

        $factor = $this->totp->enroll($user);
        $this->recoveryCodes->generate($user);

        return $factor;
    }

    public function confirm(Authenticatable $user, string $code): bool
    {
        $factor = $this->currentFactor($this->factorUser($user));

        return $factor instanceof TotpFactor && $this->totp->confirm($factor, $code);
    }

    public function disable(Authenticatable $user): void
    {
        $user = $this->factorUser($user);
        $this->totp->disableAll($user);
        $user->recoveryCodes()->delete();
    }

    /**
     * @return list<string>
     */
    public function recoveryCodes(Authenticatable $user): array
    {
        return $this->factorUser($user)->recoveryCodes()
            ->whereNull('used_at')
            ->get()
            ->pluck('code')
            ->all();
    }

    /**
     * @return list<string>
     */
    public function regenerateRecoveryCodes(Authenticatable $user): array
    {
        return $this->recoveryCodes->generate($this->factorUser($user));
    }

    public function currentFactor(Authenticatable $user): ?TotpFactor
    {
        return $this->factorUser($user)->totpFactors()->latest('id')->first();
    }
}

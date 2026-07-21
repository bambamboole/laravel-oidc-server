<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor;

use Bambamboole\LaravelOidc\Auth\MultiFactor\Concerns\InteractsWithFactorUser;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\FactorProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class RecoveryCodeProvider implements FactorProvider
{
    use InteractsWithFactorUser;

    public function key(): string
    {
        return 'recovery_code';
    }

    public function isBackup(): bool
    {
        return true;
    }

    /**
     * @return list<string>
     */
    public function generate(Authenticatable $user): array
    {
        $user = $this->factorUser($user);
        $codes = collect()->times(
            (int) config('oidc.auth.two_factor.recovery_codes', 8),
            static fn (): string => Str::random(10).'-'.Str::random(10),
        )->all();

        DB::transaction(function () use ($user, $codes): void {
            $user->recoveryCodes()->delete();
            $user->recoveryCodes()->createMany(array_map(
                static fn (string $code): array => ['code' => $code],
                $codes,
            ));
        });

        return $codes;
    }

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        $user = $this->factorUser($user);

        if (! $user->totpFactors()->whereNotNull('confirmed_at')->exists() || ! $user->recoveryCodes()->exists()) {
            return [];
        }

        return [new FactorEnrollment($this->key(), 'account', 'Recovery code', now(), null)];
    }

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
    {
        return new FactorChallenge($enrollment, ['input' => 'recovery_code']);
    }

    public function verify(Authenticatable $user, FactorChallenge $challenge, FactorResponse $response): FactorVerification
    {
        $user = $this->factorUser($user);
        $submittedCode = $response->string('recovery_code');

        if ($submittedCode === '') {
            return new FactorVerification(false);
        }

        $lockKey = 'oidc.recovery_codes.'.md5($user::class.':'.$user->getAuthIdentifier());
        $verified = Cache::lock($lockKey, 10)->block(10, function () use ($user, $submittedCode): bool {
            return DB::transaction(function () use ($user, $submittedCode): bool {
                $codes = $user->recoveryCodes()->whereNull('used_at')->lockForUpdate()->get();

                foreach ($codes as $code) {
                    if (! hash_equals($code->code, $submittedCode)) {
                        continue;
                    }

                    $code->forceFill(['used_at' => now()])->save();

                    return true;
                }

                return false;
            });
        });

        return new FactorVerification($verified, $verified ? ['otp'] : [], ['backup' => true]);
    }
}

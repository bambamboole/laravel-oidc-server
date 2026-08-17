<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Data\EnrollmentOption;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Models\RecoveryCode;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;

class RecoveryCodeProvider implements EnrollableFactorProvider
{
    public function key(): string
    {
        return 'recovery_code';
    }

    public function isBackup(): bool
    {
        return true;
    }

    /**
     * Recovery codes are backfilled once the first real factor is confirmed,
     * so they are never something the user picks from a method list.
     *
     * @return list<EnrollmentOption>
     */
    public function enrollmentOptions(): array
    {
        return [];
    }

    /**
     * @return list<string>
     */
    public function generate(Authenticatable $user): array
    {
        $codes = collect()->times(
            (int) config('oidc.auth.two_factor.recovery_codes', 8),
            static fn (): string => Str::random(10).'-'.Str::random(10),
        )->all();

        DB::transaction(function () use ($user, $codes): void {
            $this->recoveryCodes($user)->delete();
            $this->recoveryCodes($user)->createMany(array_map(
                static fn (string $code): array => ['code' => $code],
                $codes,
            ));
        });

        return $codes;
    }

    /**
     * The user's unused recovery codes.
     *
     * @return list<string>
     */
    public function codes(Authenticatable $user): array
    {
        return $this->recoveryCodes($user)
            ->whereNull('used_at')
            ->pluck('code')
            ->all();
    }

    /**
     * How many of the current set are still usable, and how big the set was when
     * it was generated. Counting rows rather than reading the configured size
     * keeps the answer true for a set generated under an older setting.
     */
    public function remaining(Authenticatable $user): int
    {
        return $this->recoveryCodes($user)->whereNull('used_at')->count();
    }

    public function total(Authenticatable $user): int
    {
        return $this->recoveryCodes($user)->count();
    }

    /**
     * A single account-wide enrollment whenever codes exist. The
     * EnrollmentPolicy owns the lifecycle (backfilled with the first
     * confirmed factor, removed with the last), so existence of codes is the
     * whole gate — any factor type covers them, not just TOTP.
     *
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        if (! $this->recoveryCodes($user)->exists()) {
            return [];
        }

        return [new FactorEnrollment($this->key(), 'account', 'Recovery code', now(), null)];
    }

    /**
     * Enrolling (re)generates the code set — the codes appear only in this
     * return value's metadata, never in enrollments().
     */
    public function beginEnrollment(Authenticatable $user, ?EnrollmentOption $option = null, ?string $name = null): FactorEnrollment
    {
        return new FactorEnrollment($this->key(), 'account', 'Recovery code', now(), null, [
            'codes' => $this->generate($user),
        ]);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, array $input): bool
    {
        return true;
    }

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void
    {
        $this->clear($user);
    }

    public function clear(Authenticatable $user): void
    {
        $this->recoveryCodes($user)->delete();
    }

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
    {
        return new FactorChallenge($enrollment, ['input' => 'recovery_code']);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function verify(Authenticatable $user, FactorChallenge $challenge, array $input): FactorVerification
    {
        $submittedCode = $input['recovery_code'] ?? null;

        if (! is_string($submittedCode) || $submittedCode === '') {
            return new FactorVerification(false);
        }

        $lockKey = 'oidc.recovery_codes.'.md5($user::class.':'.$user->getAuthIdentifier());
        $verified = Cache::lock($lockKey, 10)->block(10, function () use ($user, $submittedCode): bool {
            return DB::transaction(function () use ($user, $submittedCode): bool {
                $codes = $this->recoveryCodes($user)->whereNull('used_at')->lockForUpdate()->get();

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

        return new FactorVerification($verified, $verified ? ['otp'] : []);
    }

    /**
     * The provider owns its storage: the relation is built here, so the user
     * model needs no factor-specific methods — any Eloquent authenticatable
     * works.
     *
     * @return MorphMany<RecoveryCode, covariant Model>
     */
    private function recoveryCodes(Authenticatable $user): MorphMany
    {
        if (! $user instanceof Model) {
            throw new LogicException('The authenticatable must be an Eloquent model to store recovery codes.');
        }

        return $user->morphMany(RecoveryCode::class, 'authenticatable');
    }
}

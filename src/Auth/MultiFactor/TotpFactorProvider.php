<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Concerns\InteractsWithFactorUser;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\FactorAuthenticatable;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Models\TotpFactor;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use LogicException;
use PragmaRX\Google2FA\Google2FA;

class TotpFactorProvider implements EnrollableFactorProvider
{
    use InteractsWithFactorUser;

    public function __construct(private readonly Google2FA $engine) {}

    public function key(): string
    {
        return 'totp';
    }

    public function isBackup(): bool
    {
        return false;
    }

    public function enroll(Authenticatable $user, ?string $name = null): TotpFactor
    {
        $user = $this->factorUser($user);

        return $user->totpFactors()->create([
            'name' => $name ?? 'Authenticator app',
            'secret' => $this->engine->generateSecretKey((int) config('oidc.auth.two_factor.secret_length', 16)),
        ]);
    }

    public function beginEnrollment(Authenticatable $user, ?string $name = null): FactorEnrollment
    {
        return $this->toEnrollment($this->enroll($user, $name));
    }

    public function confirm(TotpFactor $factor, string $code): bool
    {
        if (! $this->engine->verifyKey($factor->secret, $code, $this->window())) {
            return false;
        }

        $factor->forceFill(['confirmed_at' => now()])->save();

        return true;
    }

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void
    {
        $this->factorFor($this->factorUser($user), $enrollment)->delete();
    }

    public function disableAll(Authenticatable $user): void
    {
        $this->factorUser($user)->totpFactors()->delete();
    }

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        $user = $this->factorUser($user);

        return $user->totpFactors()->get()
            ->map(fn (TotpFactor $factor): FactorEnrollment => $this->toEnrollment($factor))
            ->all();
    }

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
    {
        $this->factorFor($this->factorUser($user), $enrollment);

        return new FactorChallenge($enrollment, ['input' => 'code']);
    }

    public function verify(Authenticatable $user, FactorChallenge $challenge, FactorResponse $response): FactorVerification
    {
        $factorUser = $this->factorUser($user);
        $code = $response->string('code');

        if ($code === '') {
            return new FactorVerification(false);
        }

        $verified = DB::transaction(function () use ($factorUser, $challenge, $code): bool {
            $factor = $factorUser->totpFactors()
                ->whereKey($challenge->enrollment->id)
                ->whereNotNull('confirmed_at')
                ->lockForUpdate()
                ->first();

            if (! $factor instanceof TotpFactor) {
                return false;
            }

            $timestamp = $this->engine->verifyKeyNewer(
                $factor->secret,
                $code,
                $factor->last_used_timestep,
                $this->window(),
            );

            if ($timestamp === false) {
                return false;
            }

            $factor->forceFill([
                'last_used_timestep' => $timestamp === true ? $this->engine->getTimestamp() : $timestamp,
                'last_used_at' => now(),
            ])->save();

            return true;
        });

        return new FactorVerification($verified, $verified ? ['otp'] : []);
    }

    public function qrCodeUrl(TotpFactor $factor, Authenticatable $user): string
    {
        $username = method_exists($user, 'getPasskeyUsername')
            ? $user->getPasskeyUsername()
            : (string) $user->getAuthIdentifier();

        return $this->engine->getQRCodeUrl((string) config('app.name'), $username, $factor->secret);
    }

    public function qrCodeSvg(TotpFactor $factor, Authenticatable $user): string
    {
        $writer = new Writer(new ImageRenderer(new RendererStyle(192, 0), new SvgImageBackEnd));

        return $writer->writeString($this->qrCodeUrl($factor, $user));
    }

    private function window(): int
    {
        return (int) config('oidc.auth.two_factor.window', 1);
    }

    private function factorFor(FactorAuthenticatable $user, FactorEnrollment $enrollment): TotpFactor
    {
        if ($enrollment->providerKey !== $this->key()) {
            throw new LogicException('The enrollment does not belong to the TOTP provider.');
        }

        return $user->totpFactors()->whereKey($enrollment->id)->firstOrFail();
    }

    private function toEnrollment(TotpFactor $factor): FactorEnrollment
    {
        return new FactorEnrollment(
            $this->key(),
            (string) $factor->getKey(),
            $factor->name,
            $factor->confirmed_at,
            $factor->last_used_at,
        );
    }
}

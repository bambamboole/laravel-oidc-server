<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Models\TotpFactor;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Facades\DB;
use LogicException;
use PragmaRX\Google2FA\Google2FA;

class TotpFactorProvider implements EnrollableFactorProvider
{
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
        return $this->factors($user)->create([
            'name' => $name ?? 'Authenticator app',
            'secret' => $this->engine->generateSecretKey((int) config('oidc.auth.two_factor.secret_length', 16)),
        ]);
    }

    /**
     * An existing unconfirmed enrollment is returned as-is (same factor, same
     * secret) instead of stacking a new row per request, so a repeated enroll
     * call — e.g. a twice-clicked enable button — stays on one pending factor.
     * Confirmed factors are never touched; enrolling alongside one creates a
     * fresh pending row (re-enrollment), which revoke cleans up.
     */
    public function beginEnrollment(Authenticatable $user, ?string $name = null): FactorEnrollment
    {
        $factor = $this->latestPendingFactor($user) ?? $this->enroll($user, $name);
        $enrollment = $this->toEnrollment($factor);

        // The setup payload only exists at enrollment time; enrollments()
        // never exposes the secret again.
        return new FactorEnrollment(
            $enrollment->providerKey,
            $enrollment->id,
            $enrollment->label,
            $enrollment->confirmedAt,
            $enrollment->lastUsedAt,
            [
                'secret' => $factor->secret,
                'qr_svg' => $this->qrCodeSvg($factor, $user),
                'qr_url' => $this->qrCodeUrl($factor, $user),
            ],
        );
    }

    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, FactorResponse $response): bool
    {
        return $this->confirm(
            $this->factorFor($user, $enrollment),
            $response->string('code'),
        );
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
        $this->factorFor($user, $enrollment)->delete();
    }

    public function disableAll(Authenticatable $user): void
    {
        $this->factors($user)->delete();
    }

    public function latestFactor(Authenticatable $user): ?TotpFactor
    {
        return $this->factors($user)->latest('id')->first();
    }

    public function latestPendingFactor(Authenticatable $user): ?TotpFactor
    {
        return $this->factors($user)->whereNull('confirmed_at')->latest('id')->first();
    }

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        return $this->factors($user)->get()
            ->map(fn (TotpFactor $factor): FactorEnrollment => $this->toEnrollment($factor))
            ->all();
    }

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
    {
        $this->factorFor($user, $enrollment);

        return new FactorChallenge($enrollment, ['input' => 'code']);
    }

    public function verify(Authenticatable $user, FactorChallenge $challenge, FactorResponse $response): FactorVerification
    {
        $code = $response->string('code');

        if ($code === '') {
            return new FactorVerification(false);
        }

        $verified = DB::transaction(function () use ($user, $challenge, $code): bool {
            $factor = $this->factors($user)
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

    private function factorFor(Authenticatable $user, FactorEnrollment $enrollment): TotpFactor
    {
        if ($enrollment->providerKey !== $this->key()) {
            throw new LogicException('The enrollment does not belong to the TOTP provider.');
        }

        return $this->factors($user)->whereKey($enrollment->id)->firstOrFail();
    }

    /**
     * The provider owns its storage: the relation is built here, so the user
     * model needs no factor-specific methods — any Eloquent authenticatable
     * works.
     *
     * @return MorphMany<TotpFactor, covariant Model>
     */
    private function factors(Authenticatable $user): MorphMany
    {
        if (! $user instanceof Model) {
            throw new LogicException('The authenticatable must be an Eloquent model to store TOTP factors.');
        }

        return $user->morphMany(TotpFactor::class, 'authenticatable');
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

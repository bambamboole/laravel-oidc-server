<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * Keeps the signing key in `oidc_signing_keys`: exactly one active row signs,
 * every retained row stays in JWKS under its own kid so tokens issued before a
 * rotation keep verifying.
 */
final class DatabaseSigningKeyStore implements SigningKeyStore
{
    public function signingKey(): SigningKey
    {
        $record = SigningKeyRecord::query()
            ->whereNull('retired_at')
            ->whereNotNull('private_key')
            ->orderByDesc('created_at')
            ->first();

        if ($record === null) {
            throw new RuntimeException(
                'No active OIDC signing key in [oidc_signing_keys]. Run `php artisan oidc:rotate-keys`.',
            );
        }

        return $record->toSigningKey();
    }

    /** @return non-empty-list<SigningKey> */
    public function verificationKeys(): array
    {
        $signing = $this->signingKey();

        $retained = SigningKeyRecord::query()
            ->whereNotNull('retired_at')
            ->orderByDesc('retired_at')
            ->get()
            ->map(fn (SigningKeyRecord $record): SigningKey => $record->toVerificationKey())
            ->all();

        return [$signing, ...$retained];
    }

    public function rotate(GeneratedSigningKeys $keys): void
    {
        DB::transaction(function () use ($keys): void {
            SigningKeyRecord::query()->whereNull('retired_at')->update(['retired_at' => now()]);

            SigningKeyRecord::query()->create([
                'kid' => $keys->kid,
                'public_key' => $keys->publicKeyPem,
                'private_key' => $keys->privateKeyPem,
            ]);
        });
    }
}

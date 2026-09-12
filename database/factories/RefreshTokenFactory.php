<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<RefreshToken>
 */
class RefreshTokenFactory extends Factory
{
    protected $model = RefreshToken::class;

    public function definition(): array
    {
        return [
            'id' => bin2hex(random_bytes(40)),
            'realm' => RefreshToken::currentRealm(),
            'access_token_id' => AccessToken::factory(),
            'expires_at' => now()->addDays(14),
        ];
    }

    public function forAccessToken(AccessToken $accessToken): static
    {
        return $this->state(['access_token_id' => $accessToken->getKey(), 'realm' => $accessToken->realm]);
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }
}

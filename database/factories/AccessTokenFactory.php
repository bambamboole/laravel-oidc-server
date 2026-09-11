<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForClient;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<AccessToken>
 */
class AccessTokenFactory extends Factory
{
    use ForClient, ForUser;

    protected $model = AccessToken::class;

    public function definition(): array
    {
        return [
            'id' => bin2hex(random_bytes(40)),
            'realm_id' => AccessToken::currentRealm(),
            'user_id' => (string) Str::uuid(),
            'client_id' => (string) Str::uuid(),
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => now()->addHour(),
        ];
    }

    public function revoked(): static
    {
        return $this->state(['revoked' => true]);
    }

    public function expired(): static
    {
        return $this->state(['expires_at' => now()->subMinute()]);
    }
}

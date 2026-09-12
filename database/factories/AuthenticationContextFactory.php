<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<AuthenticationContext>
 */
class AuthenticationContextFactory extends Factory
{
    use ForUser;

    protected $model = AuthenticationContext::class;

    public function definition(): array
    {
        return [
            'realm' => AuthenticationContext::currentRealm(),
            'user_id' => self::newUserId(...),
            'amr' => ['pwd'],
            'auth_time' => now()->getTimestamp(),
            'id_token_claims' => [],
            'access_token_claims' => [],
            'created_at' => now(),
            'expires_at' => now()->addDays(30),
        ];
    }
}

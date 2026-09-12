<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForClient;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<AuthorizationCode>
 */
class AuthorizationCodeFactory extends Factory
{
    use ForClient, ForUser;

    protected $model = AuthorizationCode::class;

    public function definition(): array
    {
        return [
            'code' => bin2hex(random_bytes(40)),
            'realm_id' => AuthorizationCode::currentRealm(),
            'user_id' => self::newUserId(...),
            'client_id' => fn (): string => (string) Client::factory()->create()->getKey(),
            'scopes' => ['openid'],
            'code_challenge' => Str::random(43),
            'code_challenge_method' => 'S256',
            'expires_at' => now()->addMinutes(10),
        ];
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<OidcSession>
 */
class OidcSessionFactory extends Factory
{
    use ForUser;

    protected $model = OidcSession::class;

    public function definition(): array
    {
        return [
            'realm_id' => OidcSession::currentRealm(),
            'user_id' => self::newUserId(...),
            'created_at' => now(),
            'expires_at' => now()->addHour(),
        ];
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }

    public function expired(): static
    {
        return $this->state(['expires_at' => now()->subMinute()]);
    }
}

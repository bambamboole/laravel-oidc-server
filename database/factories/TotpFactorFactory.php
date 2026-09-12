<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Credentials\Models\TotpFactor;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<TotpFactor>
 */
class TotpFactorFactory extends Factory
{
    use ForUser;

    protected $model = TotpFactor::class;

    public function definition(): array
    {
        return [
            'user_id' => self::newUserId(...),
            'name' => 'Authenticator app',
            'secret' => Str::random(32),
        ];
    }

    public function confirmed(): static
    {
        return $this->state(['confirmed_at' => now()]);
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Credentials\Models\RecoveryCode;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<RecoveryCode>
 */
class RecoveryCodeFactory extends Factory
{
    use ForUser;

    protected $model = RecoveryCode::class;

    public function definition(): array
    {
        return [
            'user_id' => self::newUserId(...),
            'code' => Str::random(20),
        ];
    }

    public function used(): static
    {
        return $this->state(['used_at' => now()]);
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Credentials\Models\PasswordHistory;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * @extends Factory<PasswordHistory>
 */
class PasswordHistoryFactory extends Factory
{
    use ForUser;

    protected $model = PasswordHistory::class;

    public function definition(): array
    {
        return [
            'user_id' => self::newUserId(...),
            'hash' => Hash::make(Str::random(16)),
            'created_at' => now(),
        ];
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Authentication\Models\PasswordResetToken;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<PasswordResetToken>
 */
class PasswordResetTokenFactory extends Factory
{
    use ForUser;

    protected $model = PasswordResetToken::class;

    /** The column holds the hash `PasswordResetTokens` compares against, not the link's token. */
    public function definition(): array
    {
        return [
            'realm' => PasswordResetToken::currentRealm(),
            'user_id' => self::newUserId(...),
            'token' => hash('sha256', Str::random(64)),
            'created_at' => now(),
        ];
    }
}

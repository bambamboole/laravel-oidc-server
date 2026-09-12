<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<SocialAccount>
 */
class SocialAccountFactory extends Factory
{
    use ForUser;

    protected $model = SocialAccount::class;

    public function definition(): array
    {
        return [
            'realm' => SocialAccount::currentRealm(),
            'user_id' => self::newUserId(...),
            'provider' => 'github',
            'provider_user_id' => (string) Str::uuid(),
            'email' => Str::uuid()->toString().'@example.com',
        ];
    }
}

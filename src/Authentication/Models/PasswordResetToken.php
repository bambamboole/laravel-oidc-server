<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Models;

use Bambamboole\LaravelOidc\Server\Database\Factories\PasswordResetTokenFactory;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $realm_id
 * @property string $user_id
 * @property string $token
 * @property CarbonInterface $created_at
 */
class PasswordResetToken extends Model
{
    use BelongsToRealm, HasUuids;

    public $timestamps = false;

    /** @use HasFactory<PasswordResetTokenFactory> */
    use HasFactory;

    protected $table = 'oidc_password_reset_tokens';

    protected $guarded = [];

    protected $hidden = ['token'];

    protected static function newFactory(): PasswordResetTokenFactory
    {
        return PasswordResetTokenFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime'];
    }
}

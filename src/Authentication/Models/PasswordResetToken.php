<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Models;

use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $user_id
 * @property string $realm_id
 * @property string $token
 * @property CarbonInterface $created_at
 */
class PasswordResetToken extends Model
{
    use BelongsToRealm;

    public $incrementing = false;

    public $timestamps = false;

    protected $table = 'oidc_password_reset_tokens';

    protected $primaryKey = 'user_id';

    protected $keyType = 'string';

    protected $guarded = [];

    protected $hidden = ['token'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime'];
    }
}

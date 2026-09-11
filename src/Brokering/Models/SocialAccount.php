<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Models;

use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property string $id
 * @property string $realm_id
 * @property string $provider
 * @property string $provider_user_id
 * @property string|null $email
 * @property string|null $name
 * @property string|null $nickname
 * @property string|null $avatar
 * @property string|null $access_token
 * @property string|null $refresh_token
 * @property CarbonInterface|null $token_expires_at
 * @property array<string, mixed>|null $raw
 * @property-read Model $authenticatable
 */
class SocialAccount extends Model
{
    use BelongsToRealm, HasUuids;

    protected $table = 'oidc_social_accounts';

    protected $fillable = [
        'provider',
        'provider_user_id',
        'email',
        'name',
        'nickname',
        'avatar',
        'access_token',
        'refresh_token',
        'token_expires_at',
        'raw',
    ];

    protected $hidden = [
        'access_token',
        'refresh_token',
    ];

    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'access_token' => 'encrypted',
            'refresh_token' => 'encrypted',
            'token_expires_at' => 'datetime',
            'raw' => 'array',
        ];
    }
}

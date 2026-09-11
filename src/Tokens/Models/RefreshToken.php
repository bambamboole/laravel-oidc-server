<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Models;

use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property string $id
 * @property string $realm_id
 * @property string $access_token_id
 * @property bool $revoked
 * @property ?CarbonInterface $expires_at
 */
class RefreshToken extends Model
{
    use BelongsToRealm;

    protected $table = 'oidc_refresh_tokens';

    protected $primaryKey = 'id';

    protected $keyType = 'string';

    public $incrementing = false;

    public $timestamps = false;

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'revoked' => 'bool',
            'expires_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<AccessToken, $this> */
    public function accessToken(): BelongsTo
    {
        return $this->belongsTo(AccessToken::class, 'access_token_id');
    }
}

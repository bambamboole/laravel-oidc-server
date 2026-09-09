<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property string $access_token_id
 * @property bool $revoked
 * @property ?Carbon $expires_at
 */
class RefreshToken extends Model
{
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

    /** @return BelongsTo<Token, $this> */
    public function accessToken(): BelongsTo
    {
        return $this->belongsTo(Token::class, 'access_token_id');
    }
}

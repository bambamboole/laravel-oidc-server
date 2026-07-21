<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $sid
 * @property string $user_id
 * @property ?Carbon $created_at
 * @property ?Carbon $expires_at
 * @property ?Carbon $revoked_at
 * @property ?Carbon $logout_notified_at
 */
class OidcSession extends Model
{
    use HasUlids;

    public $timestamps = false;

    protected $table = 'oidc_sessions';

    protected $primaryKey = 'sid';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'created_at' => 'datetime',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'logout_notified_at' => 'datetime',
        ];
    }

    public function isActive(): bool
    {
        return $this->revoked_at === null
            && ($this->expires_at === null || $this->expires_at->isFuture());
    }

    /** @return array<int, string> */
    public function uniqueIds(): array
    {
        return ['sid'];
    }
}

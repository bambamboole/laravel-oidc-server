<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Models;

use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $sid
 * @property string $realm_id
 * @property string $user_id
 * @property ?CarbonInterface $created_at
 * @property ?CarbonInterface $expires_at
 * @property ?CarbonInterface $revoked_at
 * @property ?CarbonInterface $logout_notified_at
 */
class OidcSession extends Model
{
    use BelongsToRealm, HasUuids;

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

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Models;

use Bambamboole\LaravelOidc\Server\Database\Factories\OidcSessionFactory;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $realm_id
 * @property string $user_id
 * @property ?string $browser_session_id The id of the browser session the login happened in.
 * @property CarbonInterface $created_at
 * @property CarbonInterface $updated_at
 * @property ?CarbonInterface $expires_at
 * @property ?CarbonInterface $revoked_at
 * @property ?CarbonInterface $logout_notified_at
 */
class OidcSession extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<OidcSessionFactory> */
    use HasFactory;

    use MassPrunable;

    protected $table = 'oidc_sessions';

    protected $guarded = [];

    protected static function newFactory(): OidcSessionFactory
    {
        return OidcSessionFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
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

    /**
     * A session is held past its expiry until its back-channel logout has been
     * announced and the grace window has passed: a queued logout job reads the
     * row it is announcing. Participants follow through the foreign key.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        $grace = now()->subSeconds((int) config('oidc.pruning.sessions', 86400));

        return static::query()
            ->where('expires_at', '<', $grace)
            ->where('logout_notified_at', '<', $grace);
    }
}

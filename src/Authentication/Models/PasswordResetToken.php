<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Models;

use Bambamboole\LaravelOidc\Server\Database\Factories\PasswordResetTokenFactory;
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
 * @property string $token
 * @property CarbonInterface $created_at
 */
class PasswordResetToken extends Model
{
    use BelongsToRealm, HasUuids;
    use MassPrunable;

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

    /**
     * The table carries no expiry column — a link is valid for the realm's
     * `tokens.password_reset` window from when it was minted, and this prunes
     * on the deployment-wide default. It is a floor, not the authority:
     * PasswordResetTokens checks the realm's own window on every lookup.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()
            ->where('created_at', '<', now()->subSeconds((int) config('oidc.tokens.password_reset', 3600)));
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Models;

use Bambamboole\LaravelOidc\Server\Database\Factories\AuthenticationContextFactory;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $realm_id
 * @property string $user_id
 * @property ?string $session_id
 * @property list<string> $amr
 * @property ?string $acr
 * @property ?int $auth_time
 * @property array<string, mixed> $id_token_claims
 * @property array<string, mixed> $access_token_claims
 * @property CarbonInterface $created_at
 * @property ?CarbonInterface $expires_at
 */
class AuthenticationContext extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<AuthenticationContextFactory> */
    use HasFactory;

    public $timestamps = false;

    protected $table = 'oidc_authentication_contexts';

    protected $guarded = [];

    protected static function newFactory(): AuthenticationContextFactory
    {
        return AuthenticationContextFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'amr' => 'array',
            'auth_time' => 'integer',
            'id_token_claims' => 'array',
            'access_token_claims' => 'array',
            'created_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}

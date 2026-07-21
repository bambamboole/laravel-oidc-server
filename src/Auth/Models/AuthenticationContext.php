<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property string $user_id
 * @property ?string $sid
 * @property list<string> $amr
 * @property ?string $acr
 * @property ?int $auth_time
 * @property array<string, mixed> $id_token_claims
 * @property array<string, mixed> $access_token_claims
 * @property ?Carbon $created_at
 * @property ?Carbon $expires_at
 */
class AuthenticationContext extends Model
{
    use HasUlids;

    public $timestamps = false;

    protected $table = 'oidc_authentication_contexts';

    protected $guarded = [];

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

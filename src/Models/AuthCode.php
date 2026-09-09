<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Models;

use Bambamboole\LaravelOidc\Server\Realm\Concerns\BelongsToRealm;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property string $realm_id
 * @property string $user_id
 * @property string $client_id
 * @property array<int, string> $scopes
 * @property bool $revoked
 * @property ?Carbon $expires_at
 */
class AuthCode extends Model
{
    use BelongsToRealm;

    protected $table = 'oidc_auth_codes';

    protected $primaryKey = 'id';

    protected $keyType = 'string';

    public $incrementing = false;

    public $timestamps = false;

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'revoked' => 'bool',
            'expires_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<Client, $this> */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class, 'client_id');
    }
}

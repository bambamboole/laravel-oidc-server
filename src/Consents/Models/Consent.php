<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Models;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * What a user has approved for a client: the union of every scope set they
 * consented to, kept until it is withdrawn.
 *
 * @property string $id
 * @property string $realm_id
 * @property string $user_id
 * @property string $client_id The client's primary key.
 * @property list<string> $scopes
 * @property Carbon $granted_at
 * @property ?Carbon $revoked_at
 */
class Consent extends Model
{
    use BelongsToRealm, HasUuids;

    protected $table = 'oidc_consents';

    public $timestamps = false;

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'granted_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<Client, $this> */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class, 'client_id');
    }

    public function isActive(): bool
    {
        return $this->revoked_at === null;
    }

    /** @param  list<string>  $scopes */
    public function covers(array $scopes): bool
    {
        return $this->isActive() && array_diff($scopes, $this->scopes) === [];
    }
}

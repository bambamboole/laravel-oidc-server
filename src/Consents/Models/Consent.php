<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Models;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * What a user has approved for a client at one resource: the union of every
 * scope set they consented to there, kept until it is withdrawn.
 *
 * The resource is part of the identity of a consent. A scope name only means
 * something at the resource that declares it, so an approval of `read` at one
 * resource server says nothing about `read` at another.
 *
 * @property string $id
 * @property string $realm_id
 * @property string $user_id
 * @property string $client_id The client's primary key.
 * @property string $resource The resource identifier the scopes were approved for.
 * @property list<string> $scopes
 * @property CarbonInterface $granted_at
 * @property ?CarbonInterface $revoked_at
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

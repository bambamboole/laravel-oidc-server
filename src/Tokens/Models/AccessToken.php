<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Models;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Carbon;

/**
 * @property string $id The token's jti.
 * @property string $realm_id
 * @property ?string $user_id
 * @property string $client_id
 * @property ?string $name
 * @property ?array<string, mixed> $context Host-defined facts a personal access token was issued with, e.g. the tenant it is bound to.
 * @property array<int, string> $scopes
 * @property ?string $auth_code_id The authorization code this token, or the refresh chain it sits in, descends from.
 * @property ?string $context_id The authentication context the token was issued under; null for a non-interactive grant.
 * @property bool $revoked
 * @property ?Carbon $expires_at
 */
class AccessToken extends Model
{
    use BelongsToRealm;

    protected $table = 'oidc_access_tokens';

    protected $primaryKey = 'id';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'context' => 'array',
            'revoked' => 'bool',
            'expires_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<Client, $this> */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class, 'client_id');
    }

    public function issuedTo(Client $client): bool
    {
        return (string) $this->client_id === (string) $client->getKey();
    }

    /** @return HasOne<RefreshToken, $this> */
    public function refreshToken(): HasOne
    {
        return $this->hasOne(RefreshToken::class, 'access_token_id');
    }

    public function isValid(): bool
    {
        return ! $this->revoked && ($this->expires_at === null || $this->expires_at->isFuture());
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes ?? [], true);
    }
}

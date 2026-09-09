<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Models;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * An authorization code as handed to the client, with everything the token
 * endpoint needs to redeem it: the PKCE challenge, the redirect URI it was
 * bound to, and the login-time facts the id_token repeats.
 *
 * @property string $id
 * @property string $realm_id
 * @property string $user_id
 * @property string $client_id
 * @property array<int, string> $scopes
 * @property ?string $redirect_uri
 * @property string $code_challenge
 * @property string $code_challenge_method
 * @property ?string $nonce
 * @property ?int $auth_time
 * @property ?string $context_id
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
            'auth_time' => 'int',
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
}

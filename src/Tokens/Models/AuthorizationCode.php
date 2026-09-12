<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Models;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Database\Factories\AuthorizationCodeFactory;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Bambamboole\LaravelOidc\Server\Tokens\Concerns\PrunesSpentRecords;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property string $id
 * @property string $code The secret the browser carries back from the redirect.
 * @property string $realm
 * @property string $user_id
 * @property string $client_id
 * @property array<int, string> $scopes
 * @property ?array<int, string> $audience The RFC 8707 resources requested at authorization; empty for the realm default.
 * @property ?string $redirect_uri
 * @property string $code_challenge
 * @property string $code_challenge_method
 * @property ?string $nonce
 * @property ?int $auth_time
 * @property ?string $context_id
 * @property ?CarbonInterface $revoked_at
 * @property ?CarbonInterface $expires_at
 * @property CarbonInterface $created_at
 * @property CarbonInterface $updated_at
 */
class AuthorizationCode extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<AuthorizationCodeFactory> */
    use HasFactory;

    use PrunesSpentRecords;

    protected $table = 'oidc_auth_codes';

    protected $guarded = [];

    protected $hidden = ['code'];

    protected static function newFactory(): AuthorizationCodeFactory
    {
        return AuthorizationCodeFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'audience' => 'array',
            'auth_time' => 'integer',
            'revoked_at' => 'datetime',
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

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }
}

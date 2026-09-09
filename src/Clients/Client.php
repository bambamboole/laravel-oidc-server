<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property string $id
 * @property string $realm_id
 * @property string $client_id
 * @property string $name
 * @property ?string $secret
 * @property ?string $provider
 * @property TokenEndpointAuthMethod $token_endpoint_auth_method
 * @property array<int, string> $redirect_uris
 * @property array<int, string> $post_logout_redirect_uris
 * @property array<int, string> $grant_types
 * @property ?array<int, string> $scopes
 * @property array<int, string> $allowed_exchange_audiences
 * @property ?string $backchannel_logout_uri
 * @property bool $backchannel_logout_session_required
 * @property bool $consent_required
 * @property ?int $access_token_ttl
 * @property ?int $id_token_ttl
 * @property ?int $refresh_token_ttl
 * @property ?string $provisioning_key
 * @property bool $revoked
 * @property ?string $owner_type
 * @property ?string $owner_id
 */
class Client extends Model
{
    use BelongsToRealm, HasUuids;

    protected $table = 'oidc_clients';

    protected $guarded = [];

    protected $hidden = ['secret'];

    /** Readable only on the instance that set it; the column holds a hash. */
    public ?string $plainSecret = null;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'redirect_uris' => 'array',
            'post_logout_redirect_uris' => 'array',
            'grant_types' => 'array',
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::class,
            'scopes' => 'array',
            'allowed_exchange_audiences' => 'array',
            'backchannel_logout_session_required' => 'bool',
            'consent_required' => 'bool',
            'revoked' => 'bool',
        ];
    }

    /** @return MorphTo<Model, $this> */
    public function owner(): MorphTo
    {
        return $this->morphTo('owner');
    }

    /** @return HasMany<Token, $this> */
    public function tokens(): HasMany
    {
        return $this->hasMany(Token::class, 'client_id');
    }

    /** @return HasMany<AuthCode, $this> */
    public function authCodes(): HasMany
    {
        return $this->hasMany(AuthCode::class, 'client_id');
    }

    /** @return Attribute<never, ?string> */
    protected function secret(): Attribute
    {
        return Attribute::make(
            set: function (?string $value): ?string {
                $this->plainSecret = $value;

                return $this->castAttributeAsHashedString('secret', $value);
            },
        );
    }

    /** A client nobody owns is first party. */
    public function firstParty(): bool
    {
        return $this->owner_id === null;
    }

    public function confidential(): bool
    {
        return ! empty($this->getAttributes()['secret'] ?? null);
    }

    /** A client may be configured to bypass the consent screen entirely. */
    public function skipsConsent(): bool
    {
        return ! $this->consent_required;
    }

    public function hasGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grant_types, true);
    }

    /** An unset scope list means the client may request anything the provider knows. */
    public function hasScope(string $scope): bool
    {
        return $this->scopes === null || in_array($scope, $this->scopes, true);
    }
}

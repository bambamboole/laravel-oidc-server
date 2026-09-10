<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Models;

use Bambamboole\LaravelOidc\Server\Clients\Enums\TokenEndpointAuthMethod;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
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
 * @property TokenEndpointAuthMethod $token_endpoint_auth_method
 * @property array<int, string> $redirect_uris
 * @property array<int, string> $post_logout_redirect_uris
 * @property array<int, string> $grant_types
 * @property array<int, string> $default_scopes
 * @property array<int, string> $optional_scopes
 * @property array<int, string> $allowed_exchange_audiences
 * @property ?string $backchannel_logout_uri
 * @property bool $backchannel_logout_session_required
 * @property bool $consent_required
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
            'default_scopes' => 'array',
            'optional_scopes' => 'array',
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

    /** @return HasMany<AccessToken, $this> */
    public function tokens(): HasMany
    {
        return $this->hasMany(AccessToken::class, 'client_id');
    }

    /** @return HasMany<AuthorizationCode, $this> */
    public function authCodes(): HasMany
    {
        return $this->hasMany(AuthorizationCode::class, 'client_id');
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

    public function firstParty(): bool
    {
        return $this->owner_id === null;
    }

    public function confidential(): bool
    {
        return ! empty($this->getAttributes()['secret'] ?? null);
    }

    public function skipsConsent(): bool
    {
        return ! $this->consent_required;
    }

    public function hasGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grant_types, true);
    }

    /** Default scopes are granted unasked, optional ones on request; `*` among the optional scopes stands for every catalog scope. */
    public function allowsScope(string $scope): bool
    {
        return in_array($scope, $this->default_scopes, true)
            || in_array($scope, $this->optional_scopes, true)
            || in_array('*', $this->optional_scopes, true);
    }

    /** @return list<string> */
    public function assignedScopes(): array
    {
        return array_values(array_unique([...$this->default_scopes, ...$this->optional_scopes]));
    }
}

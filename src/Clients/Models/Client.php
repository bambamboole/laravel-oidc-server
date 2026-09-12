<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Models;

use Bambamboole\LaravelOidc\Server\Clients\Enums\TokenEndpointAuthMethod;
use Bambamboole\LaravelOidc\Server\Database\Factories\ClientFactory;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
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
 * @property ?CarbonInterface $revoked_at
 * @property ?string $owner_type
 * @property ?string $owner_id
 */
class Client extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<ClientFactory> */
    use HasFactory;

    protected $table = 'oidc_clients';

    protected $guarded = [];

    protected $hidden = ['secret'];

    /** Readable only on the instance that set it; the column holds a hash. */
    public ?string $plainSecret = null;

    protected static function newFactory(): ClientFactory
    {
        return ClientFactory::new();
    }

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
            'revoked_at' => 'datetime',
        ];
    }

    /** @return MorphTo<Model, $this> */
    public function owner(): MorphTo
    {
        return $this->morphTo('owner');
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

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
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

    /**
     * Default scopes are granted unasked, optional ones on request; `*` among
     * the optional scopes stands for every scope the requested resources own.
     *
     * @param  list<string>  $audiences  the resources the request is for
     */
    public function allowsScope(string $scope, array $audiences = []): bool
    {
        return in_array($scope, $this->assignedScopes($audiences), true)
            || in_array('*', $this->optionalScopes($audiences), true);
    }

    /**
     * @param  list<string>  $audiences
     * @return list<string>
     */
    public function defaultScopes(array $audiences = []): array
    {
        return $this->scopesFor($this->default_scopes, $audiences);
    }

    /**
     * @param  list<string>  $audiences
     * @return list<string>
     */
    public function optionalScopes(array $audiences = []): array
    {
        return $this->scopesFor($this->optional_scopes, $audiences);
    }

    /**
     * @param  list<string>  $audiences
     * @return list<string>
     */
    public function assignedScopes(array $audiences = []): array
    {
        return array_values(array_unique([...$this->defaultScopes($audiences), ...$this->optionalScopes($audiences)]));
    }

    /**
     * An assignment entry may name the resource that owns the scope
     * (`<resource> <scope>`, the RFC 8707 identifier first), which limits it to
     * requests for that resource; a bare entry holds under every resource. A
     * space cannot occur in a scope token (RFC 6749 §3.3), so the two forms
     * never collide.
     *
     * @param  array<int, string>  $assigned
     * @param  list<string>  $audiences
     * @return list<string>
     */
    private function scopesFor(array $assigned, array $audiences): array
    {
        $scopes = [];

        foreach ($assigned as $entry) {
            [$resource, $scope] = str_contains($entry, ' ') ? explode(' ', $entry, 2) : [null, $entry];

            if ($resource === null || in_array($resource, $audiences, true)) {
                $scopes[] = $scope;
            }
        }

        return array_values(array_unique($scopes));
    }
}

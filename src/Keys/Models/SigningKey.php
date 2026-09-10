<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Keys\Models;

use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyPair;
use Bambamboole\LaravelOidc\Server\Shared\Realms\BelongsToRealm;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property string $realm_id
 * @property string $kid
 * @property string $public_key
 * @property ?string $private_key
 * @property ?Carbon $retired_at
 * @property ?Carbon $created_at
 *
 * @method static Builder<static> query()
 */
class SigningKey extends Model
{
    use BelongsToRealm, HasUuids;

    protected $table = 'oidc_signing_keys';

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'private_key' => 'encrypted',
            'retired_at' => 'datetime',
        ];
    }

    public function toSigningKey(): SigningKeyPair
    {
        return new SigningKeyPair($this->public_key, $this->private_key, $this->kid);
    }

    public function toVerificationKey(): SigningKeyPair
    {
        return new SigningKeyPair($this->public_key, null, $this->kid);
    }
}

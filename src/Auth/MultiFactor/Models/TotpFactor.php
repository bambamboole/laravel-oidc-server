<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $name
 * @property string $secret
 * @property int|null $last_used_timestep
 * @property Carbon|null $confirmed_at
 * @property Carbon|null $last_used_at
 * @property-read Model $authenticatable
 */
class TotpFactor extends Model
{
    protected $table = 'oidc_totp_factors';

    protected $fillable = [
        'name',
        'secret',
    ];

    protected $hidden = [
        'secret',
    ];

    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'confirmed_at' => 'datetime',
            'last_used_at' => 'datetime',
            'last_used_timestep' => 'integer',
        ];
    }
}

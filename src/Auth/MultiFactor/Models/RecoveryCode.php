<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $code
 * @property Carbon|null $used_at
 * @property-read Model $authenticatable
 */
class RecoveryCode extends Model
{
    protected $table = 'oidc_recovery_codes';

    protected $fillable = [
        'code',
    ];

    protected $hidden = [
        'code',
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
            'code' => 'encrypted',
            'used_at' => 'datetime',
        ];
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property string $hash
 * @property Carbon $created_at
 * @property-read Model $authenticatable
 */
class PasswordHistory extends Model
{
    use HasUuids;

    protected $table = 'oidc_password_history';

    public $timestamps = false;

    protected $guarded = [];

    protected $hidden = ['hash'];

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
        return ['created_at' => 'datetime'];
    }
}

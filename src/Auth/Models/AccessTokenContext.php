<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property string $access_token_id
 * @property string $context_id
 * @property ?Carbon $created_at
 */
class AccessTokenContext extends Model
{
    use HasUuids;

    public $timestamps = false;

    protected $table = 'oidc_access_token_contexts';

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime'];
    }
}

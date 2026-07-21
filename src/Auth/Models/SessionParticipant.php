<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $sid
 * @property string $client_id
 * @property ?Carbon $created_at
 */
class SessionParticipant extends Model
{
    public $timestamps = false;

    protected $table = 'oidc_session_participants';

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime'];
    }
}

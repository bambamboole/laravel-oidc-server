<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $sid
 * @property string $client_id The client's primary key.
 * @property ?CarbonInterface $created_at
 */
class SessionParticipant extends Model
{
    use HasUuids;

    public $timestamps = false;

    protected $table = 'oidc_session_participants';

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime'];
    }
}

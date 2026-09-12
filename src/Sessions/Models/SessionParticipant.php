<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Models;

use Bambamboole\LaravelOidc\Server\Database\Factories\SessionParticipantFactory;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $session_id
 * @property string $client_id The client's primary key.
 * @property CarbonInterface $created_at
 */
class SessionParticipant extends Model
{
    /** @use HasFactory<SessionParticipantFactory> */
    use HasFactory;

    use HasUuids;

    public $timestamps = false;

    protected $table = 'oidc_session_participants';

    protected $guarded = [];

    protected static function newFactory(): SessionParticipantFactory
    {
        return SessionParticipantFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime'];
    }
}

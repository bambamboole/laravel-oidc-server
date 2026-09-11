<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<SessionParticipant>
 */
class SessionParticipantFactory extends Factory
{
    protected $model = SessionParticipant::class;

    public function definition(): array
    {
        return [
            'sid' => fn (): string => OidcSession::factory()->create()->sid,
            'client_id' => (string) Str::uuid(),
            'created_at' => now(),
        ];
    }

    public function inSession(OidcSession $session): static
    {
        return $this->state(['sid' => $session->sid]);
    }

    public function forClient(Client $client): static
    {
        return $this->state(['client_id' => $client->getKey()]);
    }
}

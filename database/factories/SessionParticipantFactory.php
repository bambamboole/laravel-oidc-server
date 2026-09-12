<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<SessionParticipant>
 */
class SessionParticipantFactory extends Factory
{
    protected $model = SessionParticipant::class;

    public function definition(): array
    {
        return [
            'session_id' => fn (): string => OidcSession::factory()->create()->id,
            'client_id' => fn (): string => (string) Client::factory()->create()->getKey(),
            'created_at' => now(),
        ];
    }

    public function inSession(OidcSession $session): static
    {
        return $this->state(['session_id' => $session->id]);
    }

    public function forClient(Client $client): static
    {
        return $this->state(['client_id' => $client->getKey()]);
    }
}

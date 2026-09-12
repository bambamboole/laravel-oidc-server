<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Workbench\App\Models\User;

it('creates a session, records participants idempotently, revokes and notifies', function (): void {
    config(['oidc.session.absolute_lifetime' => 3600]);
    $registry = app(OidcSessionRepository::class);

    $user = User::factory()->create();

    $sid = $registry->start((string) $user->getKey());
    $session = $registry->find($sid);
    expect($session)->toBeInstanceOf(OidcSession::class)
        ->and($session->user_id)->toBe((string) $user->getKey())
        ->and($session->expires_at->isFuture())->toBeTrue()
        ->and($session->revoked_at)->toBeNull();

    $first = (string) Client::factory()->create()->getKey();
    $second = (string) Client::factory()->create()->getKey();

    $registry->recordParticipant($sid, $first);
    $registry->recordParticipant($sid, $first);
    $registry->recordParticipant($sid, $second);
    expect($registry->participantClientIds($sid))->toEqualCanonicalizing([$first, $second]);

    $registry->revoke($sid);
    expect($registry->find($sid)->revoked_at)->not->toBeNull();

    $registry->markNotified($sid);
    expect($registry->find($sid)->logout_notified_at)->not->toBeNull();
});

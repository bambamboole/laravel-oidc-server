<?php
// tests/Auth/SessionRegistryTest.php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\Auth\SessionRegistry;

it('creates a session, records participants idempotently, revokes and notifies', function () {
    config(['oidc.session.absolute_lifetime' => 3600]);
    $registry = app(SessionRegistry::class);

    $sid = $registry->start('42');
    $session = $registry->find($sid);
    expect($session)->toBeInstanceOf(OidcSession::class)
        ->and($session->user_id)->toBe('42')
        ->and($session->expires_at->isFuture())->toBeTrue()
        ->and($session->revoked_at)->toBeNull();

    $registry->recordParticipant($sid, 'client-a');
    $registry->recordParticipant($sid, 'client-a'); // idempotent
    $registry->recordParticipant($sid, 'client-b');
    expect($registry->participantClientIds($sid))->toEqualCanonicalizing(['client-a', 'client-b']);

    $registry->revoke($sid);
    expect($registry->find($sid)->revoked_at)->not->toBeNull();

    $registry->markNotified($sid);
    expect($registry->find($sid)->logout_notified_at)->not->toBeNull();
});

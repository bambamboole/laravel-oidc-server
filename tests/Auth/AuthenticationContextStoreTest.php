<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\AuthenticationContextStore;

it('persists and reloads an authentication context', function () {
    $store = app(AuthenticationContextStore::class);

    $expiresAt = now()->addDay();

    $id = $store->create([
        'user_id' => '42',
        'sid' => null,
        'amr' => ['pwd', 'otp'],
        'acr' => '2',
        'auth_time' => 1700000000,
        'id_token_claims' => ['groups' => ['admin']],
        'access_token_claims' => ['tier' => 'gold'],
        'expires_at' => $expiresAt,
    ]);

    expect($id)->not->toBe('');

    $row = $store->find($id);
    expect($row)->not->toBeNull()
        ->and($row->user_id)->toBe('42')
        ->and($row->sid)->toBeNull()
        ->and($row->amr)->toBe(['pwd', 'otp'])
        ->and($row->acr)->toBe('2')
        ->and($row->auth_time)->toBe(1700000000)
        ->and($row->id_token_claims)->toBe(['groups' => ['admin']])
        ->and($row->access_token_claims)->toBe(['tier' => 'gold'])
        ->and($row->expires_at->timestamp)->toBe($expiresAt->timestamp);
});

it('returns null for an unknown id', function () {
    expect(app(AuthenticationContextStore::class)->find('01JUNKULIDUNKNOWN00000000'))->toBeNull();
});

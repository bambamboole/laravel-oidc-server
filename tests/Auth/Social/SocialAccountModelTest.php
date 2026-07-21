<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Social\Models\SocialAccount;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Workbench\App\Models\User;

it('links to its authenticatable and encrypts tokens at rest', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $account = new SocialAccount([
        'provider' => 'google',
        'provider_user_id' => 'g-123',
        'email' => 'm@example.com',
        'name' => 'M',
        'access_token' => 'plain-access-token',
        'refresh_token' => 'plain-refresh-token',
        'raw' => ['sub' => 'g-123'],
    ]);
    $account->authenticatable()->associate($user);
    $account->save();

    expect($account->refresh()->authenticatable->is($user))->toBeTrue()
        ->and($account->access_token)->toBe('plain-access-token')
        ->and($account->raw)->toBe(['sub' => 'g-123']);

    $stored = DB::table('oidc_social_accounts')->first();
    expect($stored->access_token)->not->toContain('plain-access-token')
        ->and($stored->refresh_token)->not->toContain('plain-refresh-token');
});

it('enforces one link per provider identity', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    foreach (range(1, 2) as $attempt) {
        $account = new SocialAccount(['provider' => 'google', 'provider_user_id' => 'g-123']);
        $account->authenticatable()->associate($user);
        $account->save();
    }
})->throws(QueryException::class);

<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Claims\DefaultClaimsResolver;
use Bambamboole\LaravelOidc\Contracts\ClaimsResolver;
use Workbench\App\Models\User;

it('is bound as the default claims resolver', function () {
    expect(app(ClaimsResolver::class)::class)->toBe(DefaultClaimsResolver::class);
});

it('maps common user attributes into scope-grouped claims', function () {
    $user = User::create([
        'name' => 'Manuel',
        'email' => 'manuel@example.com',
        'email_verified_at' => now(),
        'password' => 'secret',
    ]);

    $claims = (new DefaultClaimsResolver)->resolve($user);

    expect($claims->forScopes(['profile']))->toHaveKey('name', 'Manuel')
        ->and($claims->forScopes(['profile']))->toHaveKey('updated_at')
        ->and($claims->forScopes(['email']))->toBe(['email' => 'manuel@example.com', 'email_verified' => true])
        ->and($claims->forScopes(['profile', 'email']))->toHaveKeys(['name', 'email']);
});

it('returns no claims for scopes without claims', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    expect((new DefaultClaimsResolver)->resolve($user)->forScopes(['openid']))->toBe([]);
});

it('marks email unverified when email_verified_at is null', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    expect((new DefaultClaimsResolver)->resolve($user)->forScopes(['email']))
        ->toBe(['email' => 'm@example.com', 'email_verified' => false]);
});

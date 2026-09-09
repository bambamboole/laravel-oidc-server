<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Authentication\Actions\RegisterUser;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Workbench\App\Models\User;

it('is disabled until a CreateUser action is bound', function () {
    expect(app(RegisterUser::class)->enabled())->toBeFalse();

    createUsersUsing(fn (array $input) => User::create($input));

    expect(app(RegisterUser::class)->enabled())->toBeTrue();
});

it('lowercases the email, dispatches Registered and audits the registration', function () {
    Event::fake([Registered::class]);
    $audit = fakeAudit();
    createUsersUsing(fn (array $input) => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));

    $registered = app(RegisterUser::class)(['name' => 'M', 'email' => 'M@Example.com', 'password' => 'secret-password']);
    $user = User::query()->where('email', 'm@example.com')->firstOrFail();

    expect($registered->getAuthIdentifier())->toBe($user->getKey());
    Event::assertDispatched(Registered::class, fn (Registered $event) => $event->user->getAuthIdentifier() === $user->getKey());
    $audit->assertRecorded(AuditEventType::UserRegistered, fn ($event) => $event->userId === (string) $user->getKey());
});

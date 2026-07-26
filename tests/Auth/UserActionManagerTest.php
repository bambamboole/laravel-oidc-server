<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Auth\UserActionManager;
use Workbench\App\Models\User;

it('rejects a string that is neither a class nor a callable at registration time', function () {
    $manager = new UserActionManager;

    expect(fn () => $manager->createUsersUsing(missingClassName()))
        ->toThrow(RuntimeException::class, 'create user');
});

it('rejects a misconfigured reset password action at registration time', function () {
    $manager = new UserActionManager;

    expect(fn () => $manager->resetUserPasswordsUsing(missingClassName()))
        ->toThrow(RuntimeException::class, 'reset user password');
});

it('rejects a misconfigured social action at registration time', function () {
    $manager = new UserActionManager;

    expect(fn () => $manager->createUsersFromSocialUsing(missingClassName()))
        ->toThrow(RuntimeException::class, 'create user from social');
});

/**
 * A typo'd action class name as it would arrive from userland config. Built
 * dynamically so static analysis cannot prove it is not a class-string — the
 * runtime guard under test is exactly the check for that case.
 *
 * @return class-string
 */
function missingClassName(): string
{
    /** @var class-string */
    return 'Not\\A\\Real\\'.str_shuffle('ClassName');
}

it('accepts class-strings without resolving them at registration time', function () {
    $manager = new UserActionManager;

    $manager->createUsersUsing(WasNeverResolvedAction::class);

    expect($manager->hasCreateUserAction())->toBeTrue()
        ->and(WasNeverResolvedAction::$constructed)->toBeFalse();
});

it('reports whether a create user action is registered', function () {
    $manager = new UserActionManager;

    expect($manager->hasCreateUserAction())->toBeFalse();

    $manager->createUsersUsing(fn (array $input) => User::create($input));

    expect($manager->hasCreateUserAction())->toBeTrue();
});

class WasNeverResolvedAction
{
    public static bool $constructed = false;

    public function __construct()
    {
        self::$constructed = true;
    }

    /** @param array<string, mixed> $input */
    public function create(array $input): never
    {
        throw new RuntimeException('not under test');
    }
}

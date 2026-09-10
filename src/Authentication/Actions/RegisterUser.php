<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Authentication\Events\UserRegistered;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\PasswordCredential;
use Bambamboole\LaravelOidc\Server\Shared\Users\CreateUser;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;

/**
 * A password in the input is checked against the realm's policy before the
 * app's CreateUser action runs; the rest of the input is the action's to
 * validate. Signing the new user in is the caller's job
 * (InteractiveLoginFinalizer).
 */
final readonly class RegisterUser
{
    public function __construct(
        private Container $container,
        private PasswordCredential $passwords,
    ) {}

    public function enabled(): bool
    {
        return $this->container->bound(CreateUser::class);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function __invoke(array $input): Authenticatable
    {
        if (isset($input['email']) && is_string($input['email'])) {
            $input['email'] = strtolower($input['email']);
        }

        if (is_string($input['password'] ?? null) && $input['password'] !== '') {
            $this->passwords->validate(null, $input['password']);
        }

        $user = $this->container->make(CreateUser::class)($input);

        $this->passwords->record($user);

        event(new Registered($user));

        event(new UserRegistered((string) $user->getAuthIdentifier()));

        return $user;
    }
}

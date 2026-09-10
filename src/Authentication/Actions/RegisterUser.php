<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Users\CreateUser;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;

/**
 * Signing the new user in is the caller's job (InteractiveLoginFinalizer).
 */
final readonly class RegisterUser
{
    public function __construct(
        private Container $container,
        private Auditor $auditor,
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

        $user = $this->container->make(CreateUser::class)($input);

        event(new Registered($user));

        $this->auditor->log(AuditEventType::UserRegistered, userId: (string) $user->getAuthIdentifier());

        return $user;
    }
}

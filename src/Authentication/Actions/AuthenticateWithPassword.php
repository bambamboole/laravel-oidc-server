<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use SensitiveParameter;

/**
 * The primary password check. Returns the user on success and null on
 * failure; the failure is audited here so every caller reports it the
 * same way. Establishing the session is the caller's job.
 */
final readonly class AuthenticateWithPassword
{
    public function __construct(private Auditor $auditor) {}

    public function __invoke(
        UserProvider $users,
        string $usernameField,
        string $username,
        #[SensitiveParameter] string $password,
    ): ?Authenticatable {
        $credentials = [$usernameField => strtolower($username), 'password' => $password];
        $user = $users->retrieveByCredentials($credentials);

        if ($user === null || ! $users->validateCredentials($user, $credentials)) {
            $this->auditor->log(AuditEventType::LoginFailed, userId: $user === null ? null : (string) $user->getAuthIdentifier(), context: [
                'method' => 'pwd',
                'username' => $credentials[$usernameField],
                'reason' => 'invalid_credentials',
            ]);

            return null;
        }

        if (config('hashing.rehash_on_login', true)) {
            $users->rehashPasswordIfRequired($user, $credentials);
        }

        return $user;
    }
}

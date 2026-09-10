<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\PasswordCredential;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use SensitiveParameter;

/**
 * A failure is audited here so every caller reports it the same way;
 * establishing the session is the caller's job. A success starts the
 * password's history when the package has not tracked it yet, so the
 * realm's rotation clock runs from the first login after the upgrade.
 */
final readonly class AuthenticateWithPassword
{
    public function __construct(
        private Auditor $auditor,
        private PasswordCredential $passwords,
    ) {}

    public function __invoke(
        UserProvider $users,
        string $usernameField,
        string $username,
        #[SensitiveParameter] string $password,
    ): ?Authenticatable {
        $credentials = [$usernameField => strtolower($username), 'password' => $password];
        $user = $users->retrieveByCredentials($credentials);

        if ($user === null || ! $this->passwords->verify($user, $password)) {
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

        $this->passwords->track($user);

        return $user;
    }
}

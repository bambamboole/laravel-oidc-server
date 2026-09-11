<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Credentials;

use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\PasswordPolicy;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use SensitiveParameter;

/**
 * The password as a realm-governed credential. The application owns the
 * column the hash lives in and how it is written; this port owns
 * verification, the realm's policy, and the history behind the reuse and
 * rotation rules.
 */
interface PasswordCredential
{
    public function verify(Authenticatable $user, #[SensitiveParameter] string $password): bool;

    /**
     * Checks a new password against the realm's policy; $user enables the
     * history rule and is null at registration.
     *
     * @throws ValidationException on the `password` key
     */
    public function validate(?Authenticatable $user, #[SensitiveParameter] string $password): void;

    /** Records the password the user has now, once a change has been persisted. */
    public function record(Authenticatable $user): void;

    /**
     * Starts the history for a user the package has never seen change a
     * password, without moving the rotation clock for one it has.
     */
    public function track(Authenticatable $user): void;

    public function changedAt(Authenticatable $user): ?CarbonInterface;

    public function isExpired(Authenticatable $user): bool;

    public function policy(): PasswordPolicy;
}

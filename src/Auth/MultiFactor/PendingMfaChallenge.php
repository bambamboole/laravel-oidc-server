<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor;

/**
 * The session-held state between an interactive login that requires a second
 * factor and the challenge verification that completes it. Owns every
 * `login.*` session key.
 */
final readonly class PendingMfaChallenge
{
    private const string USER_ID_KEY = 'login.id';

    private const string REMEMBER_KEY = 'login.remember';

    private const string FACTOR_KEY = 'login.factor';

    private const string FACTOR_ID_KEY = 'login.factor_id';

    private const string CHALLENGE_STATE_KEY = 'login.challenge_state';

    public function __construct(
        public int|string $userId,
        public bool $remember,
        public string $factor,
        public string $factorId,
    ) {}

    public function store(): void
    {
        session()->put([
            self::USER_ID_KEY => $this->userId,
            self::REMEMBER_KEY => $this->remember,
            self::FACTOR_KEY => $this->factor,
            self::FACTOR_ID_KEY => $this->factorId,
        ]);
    }

    /**
     * The factor falls back to `totp` when the session never recorded one, so
     * a challenge seeded with only a user id verifies against the default
     * provider.
     */
    public static function find(): ?self
    {
        $userId = session()->get(self::USER_ID_KEY);

        if (! is_int($userId) && ! is_string($userId)) {
            return null;
        }

        return new self(
            userId: $userId,
            remember: (bool) session()->get(self::REMEMBER_KEY, false),
            factor: (string) session()->get(self::FACTOR_KEY, 'totp'),
            factorId: (string) session()->get(self::FACTOR_ID_KEY, ''),
        );
    }

    public static function forget(): void
    {
        session()->forget([
            self::USER_ID_KEY,
            self::REMEMBER_KEY,
            self::FACTOR_KEY,
            self::FACTOR_ID_KEY,
            self::CHALLENGE_STATE_KEY,
        ]);
    }

    /**
     * @param  array<string, mixed>  $state
     */
    public static function storeChallengeState(array $state): void
    {
        session()->put(self::CHALLENGE_STATE_KEY, $state);
    }

    /**
     * Read-and-clear: consuming the private state forces every verification
     * attempt to obtain a fresh challenge.
     *
     * @return array<string, mixed>
     */
    public static function pullChallengeState(): array
    {
        $state = session()->pull(self::CHALLENGE_STATE_KEY);

        return is_array($state) ? $state : [];
    }
}

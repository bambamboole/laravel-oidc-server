<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Purge;

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Authentication\Models\PasswordResetToken;
use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Credentials\Models\PasswordHistory;
use Bambamboole\LaravelOidc\Server\Credentials\Models\RecoveryCode;
use Bambamboole\LaravelOidc\Server\Credentials\Models\TotpFactor;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;

/**
 * Deletes everything the package holds for a user, the clients the user
 * registered included; the user row itself is the application's. It does not
 * tell relying parties the sessions are gone — end them first when they
 * should hear about it.
 *
 * Deleting the user instead would do the same through the `user_id` foreign
 * key, except for the clients, which the user owns through a polymorphic
 * column that cannot cascade.
 */
final readonly class PurgeUser
{
    /**
     * A session takes its participants and authentication contexts with it, an
     * access token its refresh token.
     */
    private const array USER_OWNED = [
        OidcSession::class,
        AccessToken::class,
        AuthorizationCode::class,
        Consent::class,
        AuthenticationContext::class,
        PasswordResetToken::class,
        SocialAccount::class,
        PasswordHistory::class,
        TotpFactor::class,
        RecoveryCode::class,
    ];

    public function __construct(private PurgeClient $purgeClient) {}

    public function __invoke(Authenticatable $user): void
    {
        $id = (string) $user->getAuthIdentifier();

        DB::transaction(function () use ($user, $id): void {
            Client::query()
                ->where('owner_type', $user::class)
                ->where('owner_id', $id)
                ->each(fn (Client $client) => ($this->purgeClient)($client));

            foreach (self::USER_OWNED as $model) {
                $model::query()->where('user_id', $id)->delete();
            }
        });
    }
}

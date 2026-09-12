<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Purge;

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Authentication\Models\PasswordResetToken;
use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\SigningKeys\Models\SigningKey;
use Illuminate\Support\Facades\DB;

/**
 * Deletes every row the package keeps under a realm: its clients, keys,
 * sessions, tokens and consents. Password history and second factors belong
 * to a user rather than a realm — purge the realm's users first.
 *
 * A deployment that gave `realm` a foreign key through `oidc.migrations`
 * does not need this: deleting its own realm row cascades the same rows.
 */
final readonly class PurgeRealm
{
    /**
     * What is left once the two roots are gone. Tokens, codes, consents and
     * session participations hang off a client; participants and contexts
     * bound to a session hang off that session.
     */
    private const array REALM_SCOPED = [
        AuthenticationContext::class,
        PasswordResetToken::class,
        SocialAccount::class,
        SigningKey::class,
    ];

    public function __invoke(string $realm): void
    {
        DB::transaction(function () use ($realm): void {
            OidcSession::query()->where('realm', $realm)->delete();
            Client::query()->where('realm', $realm)->delete();

            foreach (self::REALM_SCOPED as $model) {
                $model::query()->where('realm', $realm)->delete();
            }
        });
    }
}

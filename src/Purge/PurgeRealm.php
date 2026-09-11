<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Purge;

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Authentication\Models\PasswordResetToken;
use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Bambamboole\LaravelOidc\Server\SigningKeys\Models\SigningKey;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Support\Facades\DB;

/**
 * Deletes every row the package keeps under a realm: its clients, keys,
 * sessions, tokens and consents. Password history and second factors belong
 * to a user rather than a realm — purge the realm's users first.
 */
final readonly class PurgeRealm
{
    private const array REALM_SCOPED = [
        RefreshToken::class,
        AccessToken::class,
        AuthorizationCode::class,
        Consent::class,
        AuthenticationContext::class,
        PasswordResetToken::class,
        SocialAccount::class,
        Client::class,
        SigningKey::class,
    ];

    public function __invoke(string $realm): void
    {
        DB::transaction(function () use ($realm): void {
            SessionParticipant::query()
                ->whereIn('sid', OidcSession::query()->where('realm_id', $realm)->select('sid'))
                ->delete();
            OidcSession::query()->where('realm_id', $realm)->delete();

            foreach (self::REALM_SCOPED as $model) {
                $model::query()->where('realm_id', $realm)->delete();
            }
        });
    }
}

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
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

/**
 * Deletes everything the package holds for a user, the clients the user
 * registered included; the user row itself is the application's. It does not
 * tell relying parties the sessions are gone — end them first when they
 * should hear about it.
 */
final readonly class PurgeUser
{
    public function __construct(private PurgeClient $purgeClient) {}

    public function __invoke(Authenticatable $user): void
    {
        $id = (string) $user->getAuthIdentifier();

        DB::transaction(function () use ($user, $id): void {
            Client::query()
                ->where('owner_type', $user::class)
                ->where('owner_id', $id)
                ->each(fn (Client $client) => ($this->purgeClient)($client));

            RefreshToken::query()
                ->whereIn('access_token_id', AccessToken::query()->where('user_id', $id)->select('id'))
                ->delete();
            AccessToken::query()->where('user_id', $id)->delete();
            AuthorizationCode::query()->where('user_id', $id)->delete();
            Consent::query()->where('user_id', $id)->delete();
            AuthenticationContext::query()->where('user_id', $id)->delete();
            SessionParticipant::query()
                ->whereIn('sid', OidcSession::query()->where('user_id', $id)->select('sid'))
                ->delete();
            OidcSession::query()->where('user_id', $id)->delete();
            PasswordResetToken::query()->whereKey($id)->delete();

            if ($user instanceof Model) {
                foreach ([SocialAccount::class, PasswordHistory::class, TotpFactor::class, RecoveryCode::class] as $model) {
                    $model::query()->whereMorphedTo('authenticatable', $user)->delete();
                }
            }
        });
    }
}

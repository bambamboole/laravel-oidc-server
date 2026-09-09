<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Tokens\Context\AccessTokenContext;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;

class PurgeTokensCommand extends Command
{
    protected $signature = 'oidc:purge
        {--revoked : Only purge revoked records}
        {--expired : Only purge expired records}
        {--hours=168 : Purge records that expired or were revoked at least this many hours ago}';

    protected $description = 'Delete revoked and expired access tokens, refresh tokens and authorization codes, and stale access-token context links';

    public function __construct(private readonly RealmResolver $realms)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $cutoff = now()->subHours((int) $this->option('hours'));
        $revokedOnly = (bool) $this->option('revoked');
        $expiredOnly = (bool) $this->option('expired');

        // Neither flag means both, mirroring how the flags read in isolation.
        $purgeRevoked = $revokedOnly || ! $expiredOnly;
        $purgeExpired = $expiredOnly || ! $revokedOnly;

        foreach ([Token::class, RefreshToken::class, AuthCode::class] as $model) {
            $deleted = $model::query()
                ->where(function (Builder $query) use ($purgeRevoked, $purgeExpired, $cutoff): void {
                    if ($purgeRevoked) {
                        $query->orWhere('revoked', true);
                    }

                    if ($purgeExpired) {
                        $query->orWhere('expires_at', '<', $cutoff);
                    }
                })
                ->delete();

            $this->components->info("Purged {$deleted} record(s) from [".(new $model)->getTable().'].');
        }

        $this->pruneContextLinks();

        return self::SUCCESS;
    }

    /**
     * Link rows outlive their authentication context so refresh can distinguish
     * "expired" from "unknown". They are retained until no live refresh token
     * could reference them: absolute session lifetime plus refresh lifetime,
     * independent of the --hours window.
     */
    private function pruneContextLinks(): void
    {
        $realm = $this->realms->current();
        $horizon = now()->subSeconds($realm->sessions()->absoluteLifetime + $realm->tokens()->refreshTokenLifetime);

        $deleted = AccessTokenContext::query()->where('created_at', '<', $horizon)->delete();

        $this->components->info("Purged {$deleted} record(s) from [".(new AccessTokenContext)->getTable().'].');
    }
}

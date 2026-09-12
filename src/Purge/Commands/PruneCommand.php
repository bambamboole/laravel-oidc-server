<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Purge\Commands;

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Authentication\Models\PasswordResetToken;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;

/**
 * Each model decides what of its own rows is spent, through `prunable()`.
 * This only names them: `model:prune` discovers models by scanning the
 * application's own namespace, so a package's are invisible to it unless
 * listed. Schedule this rather than `model:prune`, and the package can add a
 * table without every consumer editing their schedule.
 */
class PruneCommand extends Command
{
    protected $signature = 'oidc:prune
        {--chunk=1000 : The number of records to delete per query}
        {--pretend : Report what would be deleted instead of deleting it}';

    protected $description = 'Delete the OIDC records that are spent: expired contexts and reset links, announced sessions, revoked and expired tokens';

    /** @var list<class-string<Model>> */
    private const array MODELS = [
        RefreshToken::class,
        AccessToken::class,
        AuthorizationCode::class,
        AuthenticationContext::class,
        OidcSession::class,
        PasswordResetToken::class,
    ];

    public function handle(): int
    {
        return $this->call('model:prune', [
            '--model' => self::MODELS,
            '--chunk' => $this->option('chunk'),
            '--pretend' => (bool) $this->option('pretend'),
        ]);
    }
}

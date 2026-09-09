<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Context;

use Illuminate\Console\Command;

class PruneAuthenticationContextsCommand extends Command
{
    protected $signature = 'oidc:prune-authentication-contexts';

    protected $description = 'Delete expired OIDC authentication contexts.';

    public function handle(): int
    {
        $contexts = AuthenticationContext::query()->where('expires_at', '<', now())->delete();

        $this->info("Pruned {$contexts} context(s).");

        return self::SUCCESS;
    }
}

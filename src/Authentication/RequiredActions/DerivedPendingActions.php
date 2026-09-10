<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\RequiredActions;

use Bambamboole\LaravelOidc\Server\Authentication\Events\RequiredActionCompleted;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\PendingActions;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\RequiredAction;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\RequiredActionRegistry;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Unions the two ways an action becomes due: the registered actions that
 * derive it from state, and the ones the post-login pipeline asked for during
 * this login. The pipeline's are session-scoped by design — they express a
 * decision about one login attempt, not a property of the account — so they
 * are the only ones that need clearing.
 */
final readonly class DerivedPendingActions implements PendingActions
{
    public function __construct(
        private RequiredActionRegistry $registry,
        private RealmResolver $realms,
        private AuthSessionState $sessionState,
    ) {}

    public function for(Authenticatable $user): array
    {
        $requested = $this->sessionState->requestedActions();
        $realm = $this->realms->current();
        $pending = [];

        foreach ($this->registry->all() as $action) {
            if (in_array($action->key(), $requested, true) || $action->isPending($user, $realm)) {
                $pending[] = $action->key();
            }
        }

        return $pending;
    }

    public function url(Authenticatable $user): ?string
    {
        $pending = $this->for($user);
        $action = $pending === [] ? null : $this->registry->find($pending[0]);

        return $action instanceof RequiredAction ? route($action->route()) : null;
    }

    public function complete(Authenticatable $user, string $key): void
    {
        $this->sessionState->completeRequestedAction($key);

        event(new RequiredActionCompleted((string) $user->getAuthIdentifier(), $key));
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Authentication;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/**
 * The tail every required-action screen shares. Mid-login it hands back to
 * the finalizer, which either parks on the next action or completes the
 * login. From a live session there is nothing to finish: the user goes back
 * where they came from, and the authorization endpoint re-checks what is
 * still open on the way through.
 */
trait ContinuesLogin
{
    use ResolvesIdentityGuard;

    abstract private function loginFinalizer(): LoginFinalizer;

    abstract private function pendingActions(): PendingActions;

    private function continueAfterAction(Request $request, Authenticatable $user, string $completed): RedirectResponse
    {
        $this->pendingActions()->complete($user, $completed);

        $pending = PendingRequiredActions::find();

        if (! $pending instanceof PendingRequiredActions) {
            return redirect()->intended($this->homeUrl());
        }

        return match ($this->loginFinalizer()->finish($request, $user, $pending->remember)) {
            LoginOutcome::RequiredAction => redirect()->to(
                $this->pendingActions()->url($user) ?? $this->homeUrl(),
            ),
            default => redirect()->intended($this->homeUrl()),
        };
    }
}

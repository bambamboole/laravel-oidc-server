<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\Views\EmailVerificationPrompt;
use Bambamboole\LaravelOidc\Server\Authentication\Views\EmailVerificationView;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\ContinuesLogin;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\LoginFinalizer;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\PendingActions;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\RequiredActionSubject;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EmailVerificationPromptController
{
    use ContinuesLogin;

    /**
     * EmailVerificationView is resolved in __invoke() rather than injected so
     * the branch that settles the action and redirects never resolves a view
     * the request does not render.
     */
    public function __construct(
        private readonly RequiredActionSubject $subject,
        private readonly LoginFinalizer $finalizer,
        private readonly PendingActions $actions,
    ) {}

    public function __invoke(Request $request): Responsable|RedirectResponse|Response
    {
        $user = $this->subject->current($request);

        // Arriving here with the address already confirmed means the action is
        // settled — mid-login that is what finishes the ceremony.
        if ($user instanceof Authenticatable && (! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail())) {
            return $this->continueAfterAction($request, $user, 'verify_email');
        }

        $status = $request->session()->get('status');

        return app(EmailVerificationView::class)->respond(new EmailVerificationPrompt(
            status: is_string($status) ? $status : null,
        ), $request);
    }

    private function loginFinalizer(): LoginFinalizer
    {
        return $this->finalizer;
    }

    private function pendingActions(): PendingActions
    {
        return $this->actions;
    }
}

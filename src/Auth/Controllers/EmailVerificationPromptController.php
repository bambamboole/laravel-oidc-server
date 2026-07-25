<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\Views\EmailVerificationPrompt;
use Bambamboole\LaravelOidc\Auth\Views\EmailVerificationView;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EmailVerificationPromptController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly EmailVerificationView $view) {}

    public function __invoke(Request $request): Responsable|RedirectResponse|Response
    {
        $user = $this->currentUser($request);

        if ($user instanceof MustVerifyEmail && $user->hasVerifiedEmail()) {
            return redirect()->intended($this->homeUrl());
        }

        $status = $request->session()->get('status');

        return $this->view->respond(new EmailVerificationPrompt(
            status: is_string($status) ? $status : null,
        ), $request);
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Controllers;

use Bambamboole\LaravelOidc\Server\Shared\Authentication\ResolvesIdentityGuard;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\RedirectResponse;

class VerifyEmailController
{
    use ResolvesIdentityGuard;

    public function __invoke(EmailVerificationRequest $request): RedirectResponse
    {
        $request->fulfill();

        return redirect()->intended($this->homeUrl().'?verified=1');
    }
}

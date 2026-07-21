<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\AuthViewManager;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;

class EmailVerificationPromptController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly AuthViewManager $views) {}

    public function __invoke(Request $request): mixed
    {
        $user = $this->currentUser($request);

        if ($user instanceof MustVerifyEmail && $user->hasVerifiedEmail()) {
            return redirect()->intended($this->homeUrl());
        }

        return $this->views->render(AuthViewManager::VerifyEmail, $request);
    }
}

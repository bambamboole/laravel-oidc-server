<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\Actions\SendEmailVerification;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\ResolvesIdentityGuard;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\HttpException;

class SendEmailVerificationNotificationController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly SendEmailVerification $sendVerification) {}

    public function __invoke(Request $request): JsonResponse|RedirectResponse
    {
        $user = $this->currentUser($request);

        if (! $user instanceof MustVerifyEmail) {
            throw new HttpException(403);
        }

        if (! ($this->sendVerification)($user)) {
            return redirect()->intended($this->homeUrl());
        }

        if ($request->wantsJson()) {
            return new JsonResponse('', 202);
        }

        return back()->with('status', 'verification-link-sent');
    }
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Controllers;

use Bambamboole\LaravelOidc\Server\Brokering\Actions\UnlinkSocialAccount;
use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Brokering\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Brokering\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\ResolvesIdentityGuard;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class LinkedAccountController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly SocialProviderRegistry $providers,
        private readonly UnlinkSocialAccount $unlink,
    ) {}

    public function link(Request $request, string $provider): Response
    {
        $driver = $this->providers->get($provider) ?? abort(404);

        return $driver->redirect($request, PendingAuthorization::INTENT_LINK);
    }

    public function destroy(Request $request, SocialAccount $socialAccount): JsonResponse|RedirectResponse
    {
        $user = $this->currentUser($request) ?? abort(401);

        ($this->unlink)($user, $socialAccount);

        return $this->statusResponse($request, 'social-account-unlinked', 200);
    }
}

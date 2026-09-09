<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Brokering\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Brokering\SocialProviderRegistry;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class LinkedAccountController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly SocialProviderRegistry $providers,
    ) {}

    public function link(Request $request, string $provider): Response
    {
        $driver = $this->providers->get($provider) ?? abort(404);

        return $driver->redirect($request, PendingAuthorization::INTENT_LINK);
    }

    public function destroy(Request $request, SocialAccount $socialAccount): JsonResponse|RedirectResponse
    {
        $user = $this->currentUser($request);

        abort_unless($user instanceof Model && $socialAccount->authenticatable->is($user), 403);

        $socialAccount->delete();

        return $this->statusResponse($request, 'social-account-unlinked', 200);
    }
}

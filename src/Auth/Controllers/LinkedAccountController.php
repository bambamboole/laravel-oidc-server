<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\Social\Models\SocialAccount;
use Bambamboole\LaravelOidc\Auth\Social\PendingAuthorization;
use Bambamboole\LaravelOidc\Auth\Social\SocialProviderRegistry;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class LinkedAccountController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly SocialProviderRegistry $providers,
    ) {}

    public function link(Request $request, string $provider): RedirectResponse
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

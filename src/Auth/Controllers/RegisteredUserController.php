<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Controllers;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\InteractiveLoginFinalizer;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\LoginOutcome;
use Bambamboole\LaravelOidc\Server\Auth\UserActionManager;
use Bambamboole\LaravelOidc\Server\Auth\Views\RegisterView;
use Bambamboole\LaravelOidc\Server\Routing\Handler;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RegisteredUserController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly UserActionManager $actions,
        private readonly InteractiveLoginFinalizer $finalizer,
        private readonly Auditor $auditor,
    ) {}

    /**
     * RegisterView is resolved here (not via the constructor) so store() —
     * which shares this class — never eagerly resolves a view the request
     * doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        return app(RegisterView::class)->respond($request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        // Mirrors the createUserFromSocial null design: registration without a
        // configured action is disabled, not broken — so 404, not 500.
        abort_unless($this->actions->hasCreateUserAction(), 404);

        $input = array_merge($request->all(), [
            'email' => $request->string('email')->lower()->value(),
        ]);

        event(new Registered($user = $this->actions->createUser($input)));

        $this->auditor->log(AuditEventType::UserRegistered, userId: (string) $user->getAuthIdentifier());

        // The account exists either way; a postLogin denial only refuses the
        // session, so the user lands on the login page instead.
        return match ($this->finalizer->finalize($request, $user, 'pwd')) {
            LoginOutcome::Denied => $request->wantsJson()
                ? new JsonResponse('', 403)
                : redirect()->route(Handler::Login->value),
            LoginOutcome::MfaChallenge => $request->wantsJson()
                ? new JsonResponse(['two_factor' => true])
                : redirect()->route(Handler::TwoFactorLogin->value),
            LoginOutcome::LoggedIn => $request->wantsJson()
                ? new JsonResponse('', 201)
                : redirect()->intended($this->homeUrl()),
        };
    }
}

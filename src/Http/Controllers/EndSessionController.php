<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\BackChannel\BackChannelLogoutNotifier;
use Bambamboole\LaravelOidc\Issuer;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Throwable;

class EndSessionController
{
    public function __invoke(Request $request): RedirectResponse
    {
        $hint = $this->validatedHint($request);
        $redirectUri = $this->validatedPostLogoutUri($request, $hint);

        if ($this->shouldLogout($request, $hint)) {
            $sid = $hint?->claims()->get('sid');
            if (! is_string($sid) || $sid === '') {
                $sid = $request->hasSession() ? $request->session()->get('oidc.sid') : null;
            }

            if (is_string($sid) && $sid !== '') {
                app(SessionRegistry::class)->revoke($sid);
                app(BackChannelLogoutNotifier::class)->notify($sid);
            }

            Auth::guard(config('passport.guard', null))->logout();

            if ($request->hasSession()) {
                $request->session()->invalidate();
                $request->session()->regenerateToken();
            }
        }

        if ($redirectUri === null) {
            return redirect(config('oidc.logout_redirect', '/'));
        }

        $state = $request->input('state');

        if ($state === null) {
            return redirect()->away($redirectUri);
        }

        $separator = str_contains($redirectUri, '?') ? '&' : '?';

        return redirect()->away(
            $redirectUri.$separator.http_build_query(['state' => $state]),
        );
    }

    private function shouldLogout(Request $request, ?Plain $hint): bool
    {
        if ($hint !== null) {
            return $this->hintMatchesCurrentUser($hint);
        }

        // A GET without a verified hint is not proof of user intent: it can be
        // forged cross-site (e.g. an <img> tag). Only same-site POST requests,
        // which pass through the web guard's CSRF check, may log the user out.
        return $request->isMethod('post');
    }

    private function hintMatchesCurrentUser(Plain $hint): bool
    {
        $user = Auth::guard(config('passport.guard', null))->user();

        if ($user === null) {
            return true;
        }

        return (string) $hint->claims()->get('sub') === (string) $user->getAuthIdentifier();
    }

    private function validatedHint(Request $request): ?Plain
    {
        $hint = $request->input('id_token_hint');

        if (! is_string($hint) || $hint === '') {
            return null;
        }

        try {
            $token = (new Parser(new JoseEncoder))->parse($hint);
        } catch (Throwable) {
            return null;
        }

        if (! $token instanceof Plain) {
            return null;
        }

        $valid = (new Validator)->validate(
            $token,
            new SignedWith(new Sha256, InMemory::plainText(SigningKeys::publicKey())),
            new IssuedBy(Issuer::url()),
        );

        return $valid ? $token : null;
    }

    private function validatedPostLogoutUri(Request $request, ?Plain $hint): ?string
    {
        $uri = $request->input('post_logout_redirect_uri');

        if ($hint === null || $uri === null) {
            return null;
        }

        $clientId = $hint->claims()->get('aud')[0] ?? null;
        $client = $clientId !== null ? Passport::client()::query()->find($clientId) : null;

        if ($client === null) {
            return null;
        }

        $registered = json_decode((string) $client->getRawOriginal('post_logout_redirect_uris'), true) ?? [];

        return in_array($uri, $registered, true) ? $uri : null;
    }
}

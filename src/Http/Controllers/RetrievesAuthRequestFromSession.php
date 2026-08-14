<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Grant\OidcAuthorizationRequest;
use Exception;
use Illuminate\Http\Request;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Bridge\User;
use Laravel\Passport\Exceptions\InvalidAuthTokenException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

/**
 * Fork of Laravel\Passport\Http\Controllers\RetrievesAuthRequestFromSession that adds
 * OidcAuthorizationRequest to the unserialize allow-list; Passport's whitelist omits our
 * subclass, so the persisted request would otherwise come back as __PHP_Incomplete_Class
 * and drop the nonce carried through the consent step.
 */
trait RetrievesAuthRequestFromSession
{
    private const array ALLOWED_AUTH_REQUEST_CLASSES = [
        OidcAuthorizationRequest::class,
        AuthorizationRequest::class,
        Client::class,
        Scope::class,
        User::class,
    ];

    protected function getAuthRequestFromSession(Request $request): AuthorizationRequestInterface
    {
        if ($request->isNotFilled('auth_token') ||
            $request->session()->pull('authToken') !== $request->input('auth_token')) {
            $request->session()->forget(['authToken', 'authRequest']);

            throw InvalidAuthTokenException::different();
        }

        $authRequest = $request->session()->pull('authRequest')
            ?? throw new Exception('Authorization request was not present in the session.');

        // Passport 13.x stored the request object directly in the session before it moved to
        // serialize()/unserialize() with an allow-list. Handle both so any 13.x patch works.
        if ($authRequest instanceof AuthorizationRequestInterface) {
            return $authRequest;
        }

        return unserialize($authRequest, ['allowed_classes' => self::ALLOWED_AUTH_REQUEST_CLASSES]);
    }

    /**
     * Non-destructive variant for observers (e.g. consent auditing): the
     * authoritative pull with auth_token verification stays in
     * getAuthRequestFromSession(), which Passport's parent controller runs.
     */
    protected function peekAuthRequestFromSession(Request $request): ?AuthorizationRequestInterface
    {
        $authRequest = $request->session()->get('authRequest');

        if ($authRequest instanceof AuthorizationRequestInterface) {
            return $authRequest;
        }

        if (! is_string($authRequest)) {
            return null;
        }

        $unserialized = unserialize($authRequest, ['allowed_classes' => self::ALLOWED_AUTH_REQUEST_CLASSES]);

        return $unserialized instanceof AuthorizationRequestInterface ? $unserialized : null;
    }
}

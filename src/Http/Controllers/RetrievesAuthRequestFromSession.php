<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Bambamboole\LaravelOidc\Grant\OidcAuthorizationRequest;
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

        return unserialize($authRequest, ['allowed_classes' => [
            OidcAuthorizationRequest::class,
            AuthorizationRequest::class,
            Client::class,
            Scope::class,
            User::class,
        ]]);
    }
}

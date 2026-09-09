<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Bridge\Client;
use Bambamboole\LaravelOidc\Server\Bridge\User;
use Bambamboole\LaravelOidc\Server\Exceptions\InvalidAuthTokenException;
use Bambamboole\LaravelOidc\Server\Grant\OidcAuthorizationRequest;
use Bambamboole\LaravelOidc\Server\Scopes\BridgeScope;
use Exception;
use Illuminate\Http\Request;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

/**
 * The authorize request survives the consent step as a serialized string. The
 * allow-list must name OidcAuthorizationRequest, or the request comes back as
 * __PHP_Incomplete_Class and drops the nonce it carries.
 */
trait RetrievesAuthRequestFromSession
{
    private const array ALLOWED_AUTH_REQUEST_CLASSES = [
        OidcAuthorizationRequest::class,
        AuthorizationRequest::class,
        Client::class,
        BridgeScope::class,
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

        return unserialize($authRequest, ['allowed_classes' => self::ALLOWED_AUTH_REQUEST_CLASSES]);
    }

    /**
     * Non-destructive variant for observers (e.g. consent auditing); the
     * authoritative pull with auth_token verification stays in
     * getAuthRequestFromSession().
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

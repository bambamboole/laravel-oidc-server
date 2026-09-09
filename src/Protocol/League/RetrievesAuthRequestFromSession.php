<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League;

use Bambamboole\LaravelOidc\Server\Protocol\InvalidAuthTokenException;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ClientEntity;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ScopeEntity;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\UserEntity;
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
        ClientEntity::class,
        ScopeEntity::class,
        UserEntity::class,
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
}

<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Illuminate\Http\Request;

/**
 * Resolves the `token` a client presented to the introspection or revocation
 * endpoint. RFC 7662 §2.1 and RFC 7009 §2.1 make `token_type_hint` an
 * optimisation only: the hinted type is looked up first, the other one
 * after it, and a hint the server does not know is ignored. Both endpoints
 * answer a missing token with `invalid_request` (RFC 7662 §2.3, RFC 7009
 * §2.2.1).
 */
final readonly class PresentedTokenResolver
{
    private const string ACCESS_TOKEN = 'access_token';

    private const string REFRESH_TOKEN = 'refresh_token';

    public function __construct(private TokenInspector $inspector) {}

    public function fromRequest(Request $request): ?PresentedToken
    {
        $value = $request->input('token');

        if (! is_string($value) || $value === '') {
            throw OAuthServerException::invalidRequest('The token parameter is missing.');
        }

        return $this->resolve($value, $request->input('token_type_hint'));
    }

    public function resolve(string $value, mixed $hint): ?PresentedToken
    {
        $order = $hint === self::REFRESH_TOKEN
            ? [self::REFRESH_TOKEN, self::ACCESS_TOKEN]
            : [self::ACCESS_TOKEN, self::REFRESH_TOKEN];

        foreach ($order as $type) {
            $presented = $type === self::ACCESS_TOKEN ? $this->accessToken($value) : $this->refreshToken($value);

            if ($presented !== null) {
                return $presented;
            }
        }

        return null;
    }

    private function accessToken(string $value): ?PresentedToken
    {
        $jwt = $this->inspector->parse($value);
        $token = $jwt !== null ? $this->inspector->tokenForParsed($jwt) : null;

        return $jwt !== null && $token !== null ? PresentedToken::accessToken($jwt, $token) : null;
    }

    private function refreshToken(string $value): ?PresentedToken
    {
        $refreshToken = RefreshToken::query()
            ->inRealm()
            ->with('accessToken.client')
            ->find($value);
        $accessToken = $refreshToken?->accessToken;

        return $refreshToken instanceof RefreshToken && $accessToken instanceof Token
            ? PresentedToken::refreshToken($refreshToken, $accessToken)
            : null;
    }
}

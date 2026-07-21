<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Middleware;

use Bambamboole\LaravelOidc\Http\OAuthError;
use Bambamboole\LaravelOidc\Token\ResolvesTokenUser;
use Bambamboole\LaravelOidc\Token\TokenInspector;
use Closure;
use DateTimeInterface;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Self-contained RFC 9068 resource-server validator for a bearer access token: verifies the OP
 * signature, the at+jwt typ, expiry, revocation, and that the token is addressed to one of the
 * given audiences. It does NOT require auth:api to precede it — an exchanged token's aud is a
 * resource audience rather than a client id, which auth:api rejects. Revocation is checked against
 * the OP's own token store, so this suits a resource server that shares (or is) the OP; a fully
 * external RS would validate via token introspection instead.
 */
class CheckAudience
{
    use ResolvesTokenUser;

    public function __construct(private readonly TokenInspector $inspector) {}

    public static function using(string ...$audiences): string
    {
        return static::class.':'.implode(',', $audiences);
    }

    public function handle(Request $request, Closure $next, string ...$audiences): Response
    {
        $jwt = $request->bearerToken();

        if ($jwt === null) {
            OAuthError::bearer('invalid_token', 401);
        }

        $parsed = $this->inspector->parse($jwt);

        if ($parsed === null || $parsed->headers()->get('typ') !== 'at+jwt') {
            OAuthError::bearer('invalid_token', 401);
        }

        $exp = $parsed->claims()->get('exp');
        $expiry = $exp instanceof DateTimeInterface ? $exp->getTimestamp() : (is_numeric($exp) ? (int) $exp : 0);

        if ($expiry <= time()) {
            OAuthError::bearer('invalid_token', 401);
        }

        $token = $this->inspector->tokenForParsed($parsed);

        if ($token === null || $token->getAttribute('revoked')) {
            OAuthError::bearer('invalid_token', 401);
        }

        $tokenAudiences = $this->normalize($parsed->claims()->get('aud'));

        if (array_intersect($audiences, $tokenAudiences) === []) {
            OAuthError::bearer('insufficient_scope', 403);
        }

        $sub = $parsed->claims()->get('sub');
        $user = $this->resolveUser(is_string($sub) ? $sub : null);

        if ($user === null) {
            OAuthError::bearer('invalid_token', 401);
        }

        $request->setUserResolver(fn () => $user);

        return $next($request);
    }

    /** @return string[] */
    private function normalize(mixed $aud): array
    {
        return array_values(array_filter(is_array($aud) ? $aud : [$aud], 'is_string'));
    }
}

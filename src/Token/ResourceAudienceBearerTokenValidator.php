<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Bambamboole\LaravelOidc\Server\Issuer;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

/**
 * Extends Passport's bearer validator to also accept RFC 8693-exchanged tokens whose `aud` is a
 * resource audience rather than a client id. parent::validateAuthorization() already verified the
 * signature, expiry, and revocation, and set `oauth_client_id` from `aud[0]`; when that value isn't
 * a client id (a resource-audience token), this re-parses the already-verified JWT to read the
 * RFC 9068 `client_id` claim and, only if the audience names this server, substitutes it so
 * Passport's TokenGuard can resolve the acting client. Foreign audiences fall through unchanged and
 * keep 401ing exactly as before.
 */
class ResourceAudienceBearerTokenValidator extends BearerTokenValidator
{
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        $request = parent::validateAuthorization($request);

        $claims = $this->parsedClaims($request->getHeaderLine('authorization'));

        if ($claims === null) {
            return $request;
        }

        $audience = array_values(array_filter((array) ($claims['aud'] ?? []), 'is_string'));
        $clientId = $claims['client_id'] ?? null;

        if (! is_string($clientId) || $clientId === '' || in_array($clientId, $audience, true)) {
            return $request;
        }

        if (array_intersect($audience, $this->acceptedAudiences()) === []) {
            return $request;
        }

        return $request->withAttribute('oauth_client_id', $clientId);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function parsedClaims(string $authorizationHeader): ?array
    {
        $jwt = trim((string) preg_replace('/^\s*Bearer\s+/i', '', $authorizationHeader));

        try {
            $token = (new Parser(new JoseEncoder))->parse($jwt);
        } catch (Throwable) {
            return null;
        }

        return $token instanceof Plain ? $token->claims()->all() : null;
    }

    /**
     * @return string[]
     */
    private function acceptedAudiences(): array
    {
        $configured = array_values(array_filter((array) config('oidc.resource.audiences', []), 'is_string'));

        return [Issuer::url(), ...$configured];
    }
}

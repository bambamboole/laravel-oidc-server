<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol;

use Bambamboole\LaravelOidc\Server\Shared\Http\ConvertsPsrResponses;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Arr;
use League\OAuth2\Server\Exception\OAuthServerException as LeagueException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Renders a league exception as the HTTP response the protocol prescribes —
 * a redirect back to the client where one is known, a JSON error otherwise.
 */
final class OAuthServerException extends HttpResponseException
{
    use ConvertsPsrResponses;

    public function __construct(LeagueException $exception, bool $useFragment = false)
    {
        parent::__construct($this->convertResponse(
            $exception->generateHttpResponse(app(ResponseInterface::class), $useFragment)
        ), $exception);
    }

    public static function loginRequired(AuthorizationRequestInterface $authRequest): static
    {
        return self::forAuthRequest(
            $authRequest,
            'login_required',
            'The authorization server requires end-user authentication.',
            'The user is not authenticated',
        );
    }

    public static function consentRequired(AuthorizationRequestInterface $authRequest): static
    {
        return self::forAuthRequest(
            $authRequest,
            'consent_required',
            'The authorization server requires end-user consent.',
        );
    }

    protected static function forAuthRequest(
        AuthorizationRequestInterface $authRequest,
        string $errorType,
        string $message,
        ?string $hint = null,
    ): static {
        $exception = new LeagueException(
            $message,
            9,
            $errorType,
            401,
            $hint,
            $authRequest->getRedirectUri() ?? Arr::wrap($authRequest->getClient()->getRedirectUri())[0],
        );

        $exception->setPayload([
            'state' => $authRequest->getState(),
            ...$exception->getPayload(),
        ]);

        return new self($exception, $authRequest->getGrantTypeId() === 'implicit');
    }
}

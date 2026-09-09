<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\ConvertsPsrResponses;
use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\HandlesOAuthErrors;
use League\OAuth2\Server\AuthorizationServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;

class AccessTokenController
{
    use ConvertsPsrResponses, HandlesOAuthErrors;

    public function __construct(protected AuthorizationServer $server) {}

    public function issueToken(ServerRequestInterface $psrRequest, ResponseInterface $psrResponse): Response
    {
        return $this->withErrorHandling(fn (): Response => $this->convertResponse(
            $this->server->respondToAccessTokenRequest($psrRequest, $psrResponse)
        ));
    }
}
